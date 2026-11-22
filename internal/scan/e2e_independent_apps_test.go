// §45 multi-application acceptance tests: TWO additional fixture apps that
// differ from the bundled mock app in authentication (cookie session / HTTP
// Basic), role structure, tenant model, identifier format, endpoint
// conventions, response shape, cache behavior and API structure — to prove
// the pipeline carries no mock-app-specific assumptions.
//
//	medisys  — PROTECTED: cookie sessions, clinician/admin roles, nested
//	           patient records, file download, enforced BFLA on admin routes.
//	cloudbill— VULNERABLE + traps: Basic auth, tenant header, UUID ids,
//	           exactly one cross-identity read (CONFIRMED), a shared-cache
//	           artifact, a public-content object and a protected bulk
//	           endpoint that must all stay unconfirmed.
package scan_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/cli"
)

// ---------- medisys: protected fixture ----------

type medisysApp struct {
	mux     *http.ServeMux
	session map[string]string // sid -> uid
	role    map[string]string // uid -> role
}

func newMedisysApp() *medisysApp {
	a := &medisysApp{
		mux:     http.NewServeMux(),
		session: map[string]string{"carol-sid": "u-carol", "dave-sid": "u-dave"},
		role:    map[string]string{"u-carol": "clinician", "u-dave": "admin"},
	}
	mux := a.mux
	uid := func(r *http.Request) string {
		sid := ""
		if c, err := r.Cookie("sid"); err == nil {
			sid = c.Value
		}
		return a.session[sid]
	}
	deny := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden"})
	}
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		u := uid(r)
		if u == "" {
			deny(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"profile": map[string]any{"uid": u, "role": a.role[u]}})
	})
	// Nested patient record: owner or admin only.
	mux.HandleFunc("GET /patients/P-7/records/REC-7f3a", func(w http.ResponseWriter, r *http.Request) {
		u := uid(r)
		if u == "" {
			deny(w)
			return
		}
		if u != "u-carol" {
			deny(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"record": map[string]any{
			"id": "REC-7f3a", "patient": "P-7", "diagnosis": "hypertension stage-2", "author": "u-carol"}})
	})
	// File download under the same policy.
	mux.HandleFunc("GET /patients/P-7/records/REC-9d2c/download", func(w http.ResponseWriter, r *http.Request) {
		u := uid(r)
		if u == "" {
			deny(w)
			return
		}
		if u != "u-carol" {
			deny(w)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="lab-report-9d2c.pdf"`)
		_, _ = w.Write([]byte("%PDF-1.4 lab report for patient P-7"))
	})
	// Admin route: clinicians must be rejected (BFLA protected).
	mux.HandleFunc("GET /admin/reports", func(w http.ResponseWriter, r *http.Request) {
		u := uid(r)
		if u == "" {
			deny(w)
			return
		}
		if a.role[u] != "admin" {
			deny(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"reports": []any{"consolidated-q3"}})
	})
	return a
}

func (a *medisysApp) Handler() http.Handler { return a.mux }

func TestE2EIndependentProtectedAppNoFalsePositives(t *testing.T) {
	app := newMedisysApp()
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	base := srv.URL

	dir := t.TempDir()
	authYAML := fmt.Sprintf(`
auth:
  profiles:
    - name: carol
      type: cookie
      cookies: {"sid": "carol-sid"}
      role: clinician
      identity: {endpoint: "%s/me", method: "GET", field: "profile.uid"}
    - name: dave
      type: cookie
      cookies: {"sid": "dave-sid"}
      role: admin
      identity: {endpoint: "%s/me", method: "GET", field: "profile.uid"}
`, base, base)
	if err := os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(authYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgYAML := fmt.Sprintf(`
version: 1
session:
  name: "medisys"
  output_dir: "%s/data"
  log_level: "error"
scope:
  targets:
    - host: "%s"
      schemes: ["http"]
      include_paths: ["/"]
      allowed_methods: ["GET", "HEAD", "OPTIONS"]
  global_allowed_methods: ["GET", "HEAD", "OPTIONS"]
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
    - "%s/me"
objects:
  declared:
    - {profile: carol, resource: record, url: "%s/patients/P-7/records/REC-7f3a", identifiers: ["REC-7f3a"]}
    - {profile: carol, resource: file,   url: "%s/patients/P-7/records/REC-9d2c/download", identifiers: ["REC-9d2c"]}
verification:
  repeats: 2
  require_identity_separation: true
  cache_bust: true
  anonymous_test: true
  vertical_test: true
safety:
  dry_run: false
  allow_write_methods: false
  block_destructive_paths: true
report:
  formats: ["json"]
  title: "medisys protected"
`, dir, srv.Listener.Addr().String(), base+"/me", base, base)
	if err := os.WriteFile(filepath.Join(dir, "owntrace.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &e2eEnv{srv: srv, dir: dir}
	env.run(t, "scan")
	if env.exit != 0 {
		t.Fatalf("protected fixture must exit 0 (no CONFIRMED), got %d: %s", env.exit, env.stdout)
	}
	byURL := env.findings(t)
	for u, m := range byURL {
		if m["CONFIRMED"] {
			t.Fatalf("protected fixture produced CONFIRMED on %s: %v", u, m)
		}
	}
	if len(byURL) == 0 {
		t.Fatalf("protected fixture produced no findings at all — pipeline did not test: %s", env.stdout)
	}
}

// ---------- cloudbill: vulnerable fixture with traps ----------

type cloudbillApp struct {
	mux    *http.ServeMux
	users  map[string]string // basic user -> uid
	tenant map[string]string // uid -> tenant
	cache  map[string]string
}

func newCloudbillApp() *cloudbillApp {
	a := &cloudbillApp{
		mux:    http.NewServeMux(),
		users:  map[string]string{"usr1": "usr-771", "usr2": "usr-882"},
		tenant: map[string]string{"usr-771": "t-north", "usr-882": "t-south"},
		cache:  map[string]string{},
	}
	mux := a.mux
	basic := func(r *http.Request) string {
		u, _, ok := r.BasicAuth()
		if !ok {
			return ""
		}
		return a.users[u]
	}
	mux.HandleFunc("GET /v2/me", func(w http.ResponseWriter, r *http.Request) {
		u := basic(r)
		if u == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": u, "tenant": a.tenant[u]})
	})
	// Genuinely vulnerable single-object read (classic IDOR).
	mux.HandleFunc("GET /v2/invoices/INV-A1", func(w http.ResponseWriter, r *http.Request) {
		if basic(r) == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"invoice": map[string]any{
			"id": "INV-A1", "tenant": "t-north", "amount": "EUR 420", "customer_ref": "cust-0042"}})
	})
	// Shared-cache artifact: the FIRST requester's body is cached per path
	// and served to everyone (cache_bust query params do not bypass it).
	mux.HandleFunc("GET /v2/invoices/INV-CACHE", func(w http.ResponseWriter, r *http.Request) {
		if basic(r) == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if b, ok := a.cache["/v2/invoices/INV-CACHE"]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "HIT")
			_, _ = w.Write([]byte(b))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body := `{"invoice":{"id":"INV-CACHE","tenant":"t-north","amount":"EUR 55","customer_ref":"cust-0007"}}`
		a.cache["/v2/invoices/INV-CACHE"] = body
		_, _ = w.Write([]byte(body))
	})
	// Public content: no auth required, generic summary only.
	mux.HandleFunc("GET /public/invoices/INV-PUB", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"invoice": map[string]any{
			"id": "INV-PUB", "status": "public summary", "notice": "sensitive fields are redacted"}})
	})
	// Bulk endpoint with per-object filtering (protected bulk behavior).
	mux.HandleFunc("GET /v2/bulk", func(w http.ResponseWriter, r *http.Request) {
		u := basic(r)
		if u == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		ids := strings.Split(r.URL.Query().Get("ids"), ",")
		out := []any{}
		for _, id := range ids {
			// §23 protected bulk: each requested object is validated
			// separately against the CALLER's ownership — objects the caller
			// does not own are filtered out entirely (no existence leak).
			if id == "INV-B2" && u == "usr-771" {
				out = append(out, map[string]any{"id": id, "amount": "EUR 18", "customer_ref": "cust-0099"})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"invoices": out})
	})
	return a
}

func (a *cloudbillApp) Handler() http.Handler { return a.mux }

// findingRow is one stored finding with category-granular state.
type findingRow struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Category string `json:"category"`
	URL      string `json:"url"`
}

// findingRows loads every finding of the latest session, individually.
func findingRows(t *testing.T, env *e2eEnv) []findingRow {
	t.Helper()
	var out bytes.Buffer
	code := cli.Main([]string{"results", "list", "--json",
		"--config", filepath.Join(env.dir, "owntrace.yaml"),
		"--auth", filepath.Join(env.dir, "auth.yaml"), "--log-level", "error"}, &out, &out)
	if code != 0 {
		t.Fatalf("results list failed (exit %d): %s", code, out.String())
	}
	var parsed struct {
		Findings []findingRow `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("parse results JSON: %v\n%s", err, out.String())
	}
	return parsed.Findings
}

func TestE2EIndependentVulnerableAppWithTraps(t *testing.T) {
	app := newCloudbillApp()
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	base := srv.URL

	dir := t.TempDir()
	authYAML := fmt.Sprintf(`
auth:
  profiles:
    - name: northuser
      type: basic
      username: usr1
      password: "p1"
      role: user
      identity: {endpoint: "%s/v2/me", method: "GET", field: "sub"}
    - name: southuser
      type: basic
      username: usr2
      password: "p2"
      role: user
      identity: {endpoint: "%s/v2/me", method: "GET", field: "sub"}
`, base, base)
	if err := os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(authYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgYAML := fmt.Sprintf(`
version: 1
session:
  name: "cloudbill"
  output_dir: "%s/data"
  log_level: "error"
scope:
  targets:
    - host: "%s"
      schemes: ["http"]
      include_paths: ["/"]
      allowed_methods: ["GET", "HEAD", "OPTIONS"]
  global_allowed_methods: ["GET", "HEAD", "OPTIONS"]
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
    - "%s/v2/me"
    - "%s/v2/invoices/INV-A1"
    - "%s/public/invoices/INV-PUB"
objects:
  declared:
    - {profile: northuser, resource: invoice, url: "%s/v2/invoices/INV-A1", identifiers: ["INV-A1"]}
    - {profile: northuser, resource: invoice, url: "%s/v2/invoices/INV-CACHE", identifiers: ["INV-CACHE"]}
    - {profile: northuser, resource: invoice, url: "%s/public/invoices/INV-PUB", identifiers: ["INV-PUB"]}
    - {profile: northuser, resource: invoice, url: "%s/v2/bulk?ids=INV-B2", identifiers: ["INV-B2"]}
verification:
  repeats: 2
  require_identity_separation: true
  cache_bust: true
  anonymous_test: true
safety:
  dry_run: false
  allow_write_methods: false
  block_destructive_paths: true
report:
  formats: ["json"]
  title: "cloudbill vulnerable"
`, dir, srv.Listener.Addr().String(), base+"/v2/me", base+"/v2/invoices/INV-A1", base+"/public/invoices/INV-PUB", base, base, base, base)
	if err := os.WriteFile(filepath.Join(dir, "owntrace.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &e2eEnv{srv: srv, dir: dir}
	env.run(t, "scan")
	if env.exit != 5 {
		t.Fatalf("vulnerable fixture must exit 5 (CONFIRMED present), got %d: %s", env.exit, env.stdout)
	}
	rows := findingRows(t, env)
	horizontalConfirmed := 0
	for _, f := range rows {
		if f.Category == "horizontal_object_access" && f.State == "CONFIRMED" {
			horizontalConfirmed++
			if !strings.Contains(f.URL, "/v2/invoices/INV-A1") {
				t.Fatalf("trap confirmed as horizontally exploitable: %s (%s %s)", f.URL, f.ID, f.Category)
			}
		}
	}
	if horizontalConfirmed == 0 {
		t.Fatalf("vulnerable INV-A1 not confirmed; findings=%+v\nstdout: %s", rows, env.stdout)
	}
	// The traps must exist as tested objects (they were declared) with their
	// horizontal findings unconfirmed.
	traps := 0
	for _, f := range rows {
		if strings.Contains(f.URL, "INV-CACHE") || strings.Contains(f.URL, "INV-PUB") || strings.Contains(f.URL, "INV-B2") {
			traps++
			if f.Category == "horizontal_object_access" && f.State == "CONFIRMED" {
				t.Fatalf("trap %s horizontally confirmed", f.URL)
			}
		}
	}
	if traps == 0 {
		t.Fatalf("traps were never tested; findings=%+v", rows)
	}
}
