package verification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
)

// boplaServer builds a lab exposing an object whose `salary` property is
// readable by any authenticated principal (vulnerable property exposure).
// withSalary controls whether the property exists on the object AT ALL (the
// owner-baseline fabrication guard).
func boplaServer(withSalaryForAttacker bool) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/profile", func(w http.ResponseWriter, r *http.Request) {
		id := map[string]string{
			"Bearer tok-alice-fixed-lab-token": "usr-alice",
			"Bearer tok-bob-fixed-lab-token":   "usr-bob",
		}[r.Header.Get("Authorization")]
		if id == "" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"user":{"id":"` + id + `"}}`))
	})
	mux.HandleFunc("/api/v1/doc/d-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := `{"document":{"id":"d-1","owner":"alice","title":"Contract"`
		// The owner always sees the restricted property; the attacker sees it
		// only when the exposure bug is present (withSalaryForAttacker).
		if r.Header.Get("Authorization") == "Bearer tok-alice-fixed-lab-token" || withSalaryForAttacker {
			body += `,"salary":95000`
		}
		body += `}}`
		_, _ = w.Write([]byte(body))
	})
	return httptest.NewServer(mux)
}

// TestEngineBOPLARerouteOnDeclaredProperty proves §24: exposure of a
// DECLARED restricted property re-routes the object finding to
// broken_object_property_level_authorization with complete triage defaults,
// while the same observation WITHOUT the declaration stays object-level.
func TestEngineBOPLARerouteOnDeclaredProperty(t *testing.T) {
	run := func(declared bool) *finding.Finding {
		srv := boplaServer(true)
		defer srv.Close()
		h := newPolicyHarness(t, srv, newMemEvidenceStore(), func(c *config.Verification) {
			if declared {
				c.RestrictedProperties = []string{"salary"}
			}
		})
		item := TestItem{
			URL: srv.URL + "/api/v1/doc/d-1", Method: "GET", Resource: "document",
			Identifier: "d-1", Owner: "userA", OwnerState: ownership.StateDeclared,
			Category: finding.CatHorizontal,
		}
		return h.engine.VerifyItem(context.Background(), item)
	}

	f := run(true)
	if f.State != finding.StateConfirmed {
		t.Fatalf("declared property exposure must CONFIRM: state=%s reason=%s", f.State, f.Reason)
	}
	if f.Category != finding.CatBOPLA {
		t.Fatalf("expected BOPLA classification, got %s", f.Category)
	}
	if f.Severity != finding.DefaultSeverity(finding.CatBOPLA) || f.SeveritySrc != "default" {
		t.Fatalf("triage defaults missing: %q/%q", f.Severity, f.SeveritySrc)
	}
	if f.CWE != "CWE-200" || f.OWASP != "API3:2023" {
		t.Fatalf("CWE/OWASP mapping missing: %q/%q", f.CWE, f.OWASP)
	}

	g := run(false)
	if g.State != finding.StateConfirmed || g.Category != finding.CatHorizontal {
		t.Fatalf("undeclared exposure must stay object-level horizontal: state=%s cat=%s", g.State, g.Category)
	}
}

// TestEngineBOPLANoFabricationWithoutOwnerBaseline proves the owner-baseline
// guard: a property absent from the owner baseline (i.e. not part of the
// object's data) is never reported as "exposed" — no fabricated findings.
func TestEngineBOPLANoFabricationWithoutOwnerBaseline(t *testing.T) {
	srv := boplaServer(false) // attacker also does NOT receive salary
	defer srv.Close()
	h := newPolicyHarness(t, srv, newMemEvidenceStore(), func(c *config.Verification) {
		c.RestrictedProperties = []string{"salary"}
	})
	item := TestItem{
		URL: srv.URL + "/api/v1/doc/d-1", Method: "GET", Resource: "document",
		Identifier: "d-1", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.Category == finding.CatBOPLA {
		t.Fatalf("property missing from owner baseline was fabricated as exposure: %s", f.Reason)
	}
	if f.State != finding.StateConfirmed || f.Category != finding.CatHorizontal {
		t.Fatalf("clean object must stay horizontal CONFIRMED: state=%s cat=%s reason=%s", f.State, f.Category, f.Reason)
	}
}
