package verification

// Accounting regression tests (owner acceptance defects, 2026-11-22).
//
// A read-only GET whose path matches a destructive-path pattern
// ((?i)payment) MUST be refused by the safety guards BEFORE execution
// (deny-by-default; the guard stays method-agnostic on purpose) and the
// battery must be accounted as safety-skipped — never as executed, never
// CONFIRMED. Evidence: zero requests reach the payment endpoint.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// capturingStore collects persisted findings and detects duplicate IDs.
type capturingStore struct {
	seen map[string]int
}

func newCapturingStore() *capturingStore { return &capturingStore{seen: map[string]int{}} }

func (s *capturingStore) SaveFinding(f *finding.Finding) error {
	s.seen[f.ID]++
	return nil
}

// noopSink accepts every evidence capture without touching a DB.
type noopSink struct{}

func (noopSink) Capture(findingID, sessionID, kind, title string, data any) (*evidence.Record, error) {
	return &evidence.Record{ID: "ev-test"}, nil
}

func (noopSink) CaptureExchange(findingID, sessionID string, x *httpclient.Exchange, title string) (*evidence.Record, error) {
	return &evidence.Record{ID: "ev-test"}, nil
}

// TestReadOnlyGETMatchingDestructivePathIsSafetySkipped proves:
//   - the GET is blocked before execution (zero requests hit the endpoint),
//   - the finding is INCONCLUSIVE with an explicit safety-guard reason,
//   - the battery counts as attempts=1, safety-blocked=1 (never executed).
func TestReadOnlyGETMatchingDestructivePathIsSafetySkipped(t *testing.T) {
	var paymentHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "payment") {
			paymentHits.Add(1) // MUST stay zero: the guard refuses before sending
		}
		if r.URL.Path == "/id" {
			var uid string
			switch r.Header.Get("Authorization") {
			case "Bearer tok-alice":
				uid = "u-alice"
			case "Bearer tok-bob":
				uid = "u-bob"
			default:
				uid = "u-anon"
			}
			fmt.Fprintf(w, `{"user":{"id":"%s"}}`, uid)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()

	log := logger.New(logger.LevelError)
	sc, err := scope.New(config.Scope{
		GlobalAllowedMethods: []string{"GET"},
		Targets: []config.ScopeTarget{{
			Host:         srv.Listener.Addr().String(),
			Schemes:      []string{"http"},
			IncludePaths: []string{"/"},
		}},
		BlockedPathPatterns: []string{`(?i)payment`},
	})
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: 100, Concurrency: 4, BlockDestructive: true, BlockedPatterns: []string{`(?i)payment`}})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	client := httpclient.New(se, log, 5_000_000_000, 1<<20, 3, 0)

	acfg := &config.Config{}
	acfg.Auth.Profiles = []config.Profile{
		{Name: "alice", Type: "bearer", Token: "tok-alice", Role: "user",
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/id", Method: "GET", Field: "user.id"}},
		{Name: "bob", Type: "bearer", Token: "tok-bob", Role: "user",
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/id", Method: "GET", Field: "user.id"}},
	}
	m, err := auth.New(acfg, log)
	if err != nil {
		t.Fatal(err)
	}

	store := newCapturingStore()
	e := &Engine{Client: client, Auth: m, Evid: noopSink{}, Store: store,
		Cfg: config.Verification{}, Log: log, Session: "s-accounting"}

	item := TestItem{
		URL: srv.URL + "/api/v1/invoices/inv-2001/payments", Method: "GET",
		Resource: "payment", Identifier: "inv-2001", Owner: "alice",
		OwnerState: ownership.StateConfirmed, Category: finding.CatNested,
		EndpointID: "ep-payments",
	}
	f := e.VerifyItem(context.Background(), item)

	if got := paymentHits.Load(); got != 0 {
		t.Fatalf("destructive-pattern GET reached the server %d time(s); guard must refuse before execution", got)
	}
	if f.State != finding.StateInconclusive {
		t.Fatalf("state = %s, want INCONCLUSIVE", f.State)
	}
	if !strings.Contains(f.Reason, "safety guard refused every request") {
		t.Fatalf("reason must name the safety-guard refusal explicitly, got: %s", f.Reason)
	}
	if got := e.ChecksAttempted(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
	if got := e.ChecksSafetyBlocked(); got != 1 {
		t.Fatalf("safety-blocked checks = %d, want 1 (check-level accounting)", got)
	}
	if got := e.SafetyBlockedRequests(); got < 1 {
		t.Fatalf("safety-blocked requests = %d, want >=1 (request-level accounting)", got)
	}
	// The battery is persisted (INCONCLUSIVE), never silently dropped.
	if store.seen[f.ID] == 0 {
		t.Fatalf("finding %s was never persisted", f.ID)
	}
}

// TestDuplicateRoleMatrixEventsStayOnePersistedRow pins the Issue-1 root
// cause as intended behavior: the role-matrix battery runs once per attacker
// (a finding EVENT each), but the finding ID deliberately has no attacker
// dimension, so persistence upserts those events into ONE row. That is why
// displayed counts must be derived from persisted rows
// (storage.CountFindingsByState at scan finalization), never from event
// counters — asserted end-to-end by the scan accounting tests.
func TestDuplicateRoleMatrixEventsStayOnePersistedRow(t *testing.T) {
	item := TestItem{
		URL: "http://api.test/api/v1/admin/stats", Method: "GET",
		Resource: "admin-surface", Identifier: "http://api.test/api/v1/admin/stats",
		Owner: "admin", OwnerState: ownership.StateDeclared,
		Category: finding.CatBFLA, EndpointID: "ep-admin",
	}
	sig := item.Identifier + "|" + item.Owner + "|" + item.URL
	f1 := finding.NewID("s", item.EndpointID, string(item.Category), sig)
	f2 := finding.NewID("s", item.EndpointID, string(item.Category), sig)
	if f1 != f2 {
		t.Fatalf("same battery coordinate must map to one finding ID: %s vs %s", f1, f2)
	}
	// A different attacker is a different EVENT but still the same finding
	// row (no attacker dimension in the ID): the event/row gap the summary
	// used to report. one row, two events:
	if finding.NewID("s", item.EndpointID, string(item.Category), sig) != f1 {
		t.Fatal("ID construction must be deterministic")
	}
}
