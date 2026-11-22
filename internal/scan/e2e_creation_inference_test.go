// E2E regression tests for acceptance-matrix rows 31 and 32:
//   - Row 31: the controlled-creation workflow establishes CONFIRMED
//     ownership end-to-end through `scan`, and the write gate cannot be
//     bypassed by a weakened configuration.
//   - Row 32: listing-membership inference feeds authorization testing, and
//     inferred ownership NEVER supports CONFIRMED (§21 invariant).
//
// The fixture app is deliberately independent of the bundled mock app
// (X-Api-Key authentication, envelope-style JSON responses, string "SO-*"
// identifiers — §45 independence requirement).
package scan_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shopdevApp is an independent fixture: key-based auth, {"data": …} envelopes.
type shopdevApp struct {
	mux    *http.ServeMux
	keys   map[string]string            // api key -> owner
	orders map[string]map[string]string // id -> object-specific data (owner/total/item)
	seq    int
}

func newShopdevApp() *shopdevApp {
	a := &shopdevApp{
		mux:  http.NewServeMux(),
		keys: map[string]string{"alice-key": "alice", "bob-key": "bob"},
		orders: map[string]map[string]string{
			"SO-101": {"owner": "alice", "total": "USD 12.00", "item": "starter plan"},
			"SO-102": {"owner": "alice", "total": "USD 34.00", "item": "team plan"},
		},
	}
	mux := a.mux
	// Controlled creation endpoint (row 31): only known keys may create.
	mux.HandleFunc("POST /shop/orders", func(w http.ResponseWriter, r *http.Request) {
		owner, ok := a.keys[r.Header.Get("X-Api-Key")]
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		a.seq++
		id := fmt.Sprintf("SO-%d", a.seq)
		a.orders[id] = map[string]string{"owner": owner, "total": "USD 99.00", "item": "professional subscription"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"order": map[string]any{"id": id, "owner": owner}}})
	})
	// Listing endpoint (row 32): collection at the item base path.
	mux.HandleFunc("GET /shop/orders", func(w http.ResponseWriter, r *http.Request) {
		owner, ok := a.keys[r.Header.Get("X-Api-Key")]
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		items := []any{}
		for id, o := range a.orders {
			if o["owner"] == owner {
				items = append(items, map[string]any{"order_id": id, "total": o["total"]})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": items})
	})
	// Object read: deliberately NO authorization check (vulnerable), but
	// unknown identifiers 404 so negative controls and generic-response
	// detection can distinguish real objects from soft-404s.
	mux.HandleFunc("GET /shop/orders/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/shop/orders/")
		o, known := a.orders[id]
		if !known {
			http.Error(w, `{"error":"order not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"order": map[string]any{"id": id, "owner": o["owner"], "total": o["total"], "item": o["item"]}}})
	})
	mux.HandleFunc("GET /shop/me", func(w http.ResponseWriter, r *http.Request) {
		owner, ok := a.keys[r.Header.Get("X-Api-Key")]
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"subject": owner})
	})
	mux.HandleFunc("GET /shop/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	})
	return a
}

func (a *shopdevApp) Handler() http.Handler { return a.mux }

// runShopdev runs the real CLI scan against the shopdev app; objectsFn
// receives the concrete server base URL and returns the `objects:` YAML block.
func runShopdev(t *testing.T, objectsFn func(base string) string, allowWrite bool) *e2eEnv {
	t.Helper()
	app := newShopdevApp()
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	base := "http://" + host

	dir := t.TempDir()
	authYAML := fmt.Sprintf(`
auth:
  profiles:
    - name: alice
      type: header
      headers: {"X-Api-Key": "alice-key"}
      role: user
      identity: {endpoint: "%s/shop/me", method: "GET", field: "subject"}
    - name: bob
      type: header
      headers: {"X-Api-Key": "bob-key"}
      role: user
      identity: {endpoint: "%s/shop/me", method: "GET", field: "subject"}
`, base, base)
	if err := os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(authYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	methods := `["GET", "HEAD", "OPTIONS"]`
	if allowWrite {
		methods = `["GET", "HEAD", "OPTIONS", "POST"]`
	}
	cfgYAML := fmt.Sprintf(`
version: 1
session:
  name: "shopdev"
  output_dir: "%s/data"
  log_level: "error"
scope:
  targets:
    - host: "%s"
      schemes: ["http"]
      include_paths: ["/"]
      allowed_methods: %s
  global_allowed_methods: %s
  max_requests_total: 3000
limits:
  rate_per_second: 100
  concurrency: 4
  request_timeout_seconds: 10
auth:
  require_distinct_identities: true
discovery:
  sources: ["url"]
  seeds:
    - "%s/shop/health"
%s
verification:
  repeats: 2
  require_identity_separation: true
  cache_bust: true
  anonymous_test: true
safety:
  dry_run: false
  allow_write_methods: %t
  block_destructive_paths: true
report:
  formats: ["json"]
  title: "shopdev"
`, dir, host, methods, methods, base+"/shop/health", objectsFn(base), allowWrite)
	if err := os.WriteFile(filepath.Join(dir, "owntrace.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return &e2eEnv{srv: srv, dir: dir}
}

const creationObjectsYAML = `objects:
  creation:
    enabled: true
    endpoint: "%[1]s/shop/orders"
    method: "POST"
    body_template: '{"label":"owntrace-probe"}'
    content_type: "application/json"
    extract_field: "data.order.id"
    item_url_template: "%[1]s/shop/orders/{{id}}"
    profiles: [alice]
`

// TestE2EControlledCreationConfirmsOwnership (row 31): the controlled
// creation workflow runs end-to-end through scan — the created object is
// attributed to its creator with provenance objects.creation, authorization
// testing runs on it, and the vulnerable app yields a CONFIRMED finding on
// the created identifier.
func TestE2EControlledCreationConfirmsOwnership(t *testing.T) {
	env := runShopdev(t, func(base string) string {
		return fmt.Sprintf(creationObjectsYAML, base)
	}, true)
	env.run(t, "scan")
	if env.exit != 5 && env.exit != 0 {
		t.Fatalf("scan exit %d: %s", env.exit, env.stdout)
	}
	if !strings.Contains(env.stdout, "creation workflow confirmed 1 new object(s)") {
		t.Fatalf("creation workflow did not confirm an object: %s", env.stdout)
	}
	byURL := env.findings(t)
	found := false
	for u, m := range byURL {
		if strings.Contains(u, "/shop/orders/SO-") && m["CONFIRMED"] {
			found = true
		}
	}
	if !found {
		t.Fatalf("no CONFIRMED finding on a created object; findings=%v stdout=%s", byURL, env.stdout)
	}
}

// TestE2ECreationWriteGateCannotBeBypassed (row 31): enabling the creation
// workflow WITHOUT safety.allow_write_methods must fail validation — the
// mandatory security prerequisite is not bypassable through weakened config.
func TestE2ECreationWriteGateCannotBeBypassed(t *testing.T) {
	env := runShopdev(t, func(base string) string {
		return fmt.Sprintf(creationObjectsYAML, base)
	}, false)
	env.run(t, "scan")
	if env.exit == 0 || env.exit == 5 {
		t.Fatalf("weakened config accepted: exit=%d stdout=%s", env.exit, env.stdout)
	}
	if !strings.Contains(env.stdout, "allow_write_methods") {
		t.Fatalf("validation error must name the write gate: %s", env.stdout)
	}
}

// TestE2EListingInferenceNeverConfirms (row 32): identifiers mined from an
// authenticated listing become INFERRED ownership, authorization testing
// runs on them, and the §21 invariant holds — inferred ownership never
// supports CONFIRMED, while the same vulnerable object under DECLARED
// ownership IS confirmed (the contrast proves both sides).
func TestE2EListingInferenceNeverConfirms(t *testing.T) {
	env := runShopdev(t, func(base string) string {
		return fmt.Sprintf(`objects:
  declared:
    - {profile: alice, resource: order, url: "%s/shop/orders/SO-101", identifiers: ["SO-101"]}
  mine_collections:
    - {profile: alice, url: "%s/shop/orders", resource: order, id_fields: ["order_id"]}
`, base, base)
	}, false)
	env.run(t, "scan")
	if env.exit != 5 && env.exit != 0 {
		t.Fatalf("scan exit %d: %s", env.exit, env.stdout)
	}
	if !strings.Contains(env.stdout, "mined 2 candidate object(s)") {
		t.Fatalf("listing mining did not run: %s", env.stdout)
	}
	byURL := env.findings(t)
	declaredConfirmed, inferredTested, inferredConfirmed := false, false, false
	for u, m := range byURL {
		switch {
		case strings.HasSuffix(u, "/shop/orders/SO-101"):
			if m["CONFIRMED"] {
				declaredConfirmed = true
			}
		case strings.HasSuffix(u, "/shop/orders/SO-102"):
			inferredTested = true
			if m["CONFIRMED"] {
				inferredConfirmed = true
			}
		}
	}
	if !declaredConfirmed {
		t.Fatalf("declared object SO-101 not confirmed — contrast broken; findings=%v stdout=%s", byURL, env.stdout)
	}
	if !inferredTested {
		t.Fatalf("inferred object SO-102 was not authorization-tested; findings=%v stdout=%s", byURL, env.stdout)
	}
	if inferredConfirmed {
		t.Fatalf("§21 INVARIANT VIOLATION: inferred ownership produced CONFIRMED; findings=%v", byURL)
	}
}
