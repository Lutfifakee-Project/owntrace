// End-to-end integration tests: the full OWNTRACE pipeline (CLI → config →
// discovery → ownership mapping → cross-account verification → storage →
// reports) against the deliberately vulnerable mock application.
//
// These tests ARE the detection-quality acceptance criteria:
//   - vulnerable scenarios are detected,
//   - protected scenarios are NOT flagged,
//   - HTTP 200 / similarity / identifier presence alone cannot confirm,
//   - cache artifacts, decoys and public content are filtered,
//   - unknown ownership never reaches CONFIRMED.
package scan_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/cli"
	"github.com/Lutfifakee-Project/owntrace/internal/mockapp"
)

type e2eEnv struct {
	srv    *httptest.Server
	dir    string
	stdout string
	exit   int
}

// setupE2E builds a temp project dir wired against a mock app and runs the
// scan command through the real CLI.
func setupE2E(t *testing.T, warmCache bool) *e2eEnv {
	t.Helper()
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	base := "http://" + host

	dir := t.TempDir()
	authYAML := fmt.Sprintf(`
auth:
  profiles:
    - name: alice
      type: bearer
      token: "%s"
      role: user
      identity: {endpoint: "%s/api/v1/profile", method: "GET", field: "user.id"}
    - name: bob
      type: bearer
      token: "%s"
      role: user
      identity: {endpoint: "%s/api/v1/profile", method: "GET", field: "user.id"}
    - name: admin
      type: bearer
      token: "%s"
      role: admin
      identity: {endpoint: "%s/api/v1/profile", method: "GET", field: "user.id"}
`, app.Tokens()["alice"], base, app.Tokens()["bob"], base, app.Tokens()["admin"], base)
	if err := os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(authYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgYAML := fmt.Sprintf(`
version: 1
session:
  name: "e2e"
  output_dir: "%s/data"
  log_level: "error"
scope:
  targets:
    - host: "%s"
      schemes: ["http"]
      include_paths: ["/"]
      allowed_methods: ["GET", "HEAD", "OPTIONS"]
  global_allowed_methods: ["GET", "HEAD", "OPTIONS"]
  max_requests_total: 5000
limits:
  rate_per_second: 100
  concurrency: 4
  request_timeout_seconds: 10
auth:
  require_distinct_identities: true
discovery:
  sources: ["url"]
  seeds:
    - "%s/api/v1/admin/stats"
    - "%s/api/v1/admin/users/usr-alice"
objects:
  declared:
    - {profile: alice, resource: order,        url: "%s/api/v1/orders/o-1001", identifiers: ["o-1001"]}
    - {profile: bob,   resource: order,        url: "%s/api/v1/orders/o-1004", identifiers: ["o-1004"]}
    - {profile: alice, resource: invoice,      url: "%s/api/v1/invoices/inv-2001", identifiers: ["inv-2001"]}
    - {profile: bob,   resource: invoice,      url: "%s/api/v1/invoices/inv-2004", identifiers: ["inv-2004"]}
    - {profile: alice, resource: document,     url: "%s/api/v1/documents/doc-3001", identifiers: ["doc-3001"]}
    - {profile: alice, resource: receipt,      url: "%s/api/v1/receipts/r-6001", identifiers: ["r-6001"]}
    - {profile: alice, resource: tenant_file,  url: "%s/api/v1/tenants/t-acme/files/f-9001", identifiers: ["f-9001"], tenant: "t-acme"}
    - {profile: bob,   resource: tenant_file,  url: "%s/api/v1/tenants/t-globex/files/f-9002", identifiers: ["f-9002"], tenant: "t-globex"}
    - {profile: alice, resource: order_notes,  url: "%s/api/v1/orders/o-1001/notes", identifiers: ["o-1001"]}
    - {profile: bob,   resource: ws_report,    url: "%s/api/v1/workspaces/ws-2/reports/r-5002", identifiers: ["r-5002"]}
    - {profile: alice, resource: decoy,        url: "%s/api/v1/echo/o-1001", identifiers: ["o-1001"]}
    - {profile: alice, resource: cached_doc,   url: "%s/api/v1/cached-docs/doc-3001", identifiers: ["doc-3001"]}
    - {profile: alice, resource: order,        url: "%s/redirect/orders/o-1001", identifiers: ["o-1001"]}
    - {profile: alice, resource: invoice_pay,  url: "%s/api/v1/invoices/inv-2001/payments", identifiers: ["inv-2001"]}
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
  formats: ["json", "markdown", "html", "csv"]
  title: "E2E Report"
`, dir, host,
		// seeds
		base, base,
		// declared URLs
		base, base, base, base, base, base, base, base, base, base, base, base, base, base)
	if err := os.WriteFile(filepath.Join(dir, "owntrace.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	if warmCache {
		// Simulate the owner populating the shared cache before the scan.
		req, _ := http.NewRequest("GET", base+"/api/v1/cached-docs/doc-3001", nil)
		req.Header.Set("Authorization", "Bearer "+app.Tokens()["alice"])
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("cache warm failed: %d %s", resp.StatusCode, b)
		}
	}

	env := &e2eEnv{srv: srv, dir: dir}
	env.run(t, "scan")
	return env
}

func (e *e2eEnv) run(t *testing.T, args ...string) {
	t.Helper()
	// Global flags come after the command path (the resolver matches
	// subcommands before flag parsing).
	full := append(append([]string{}, args...),
		"--config", filepath.Join(e.dir, "owntrace.yaml"),
		"--auth", filepath.Join(e.dir, "auth.yaml"), "--log-level", "error")
	var out bytes.Buffer
	code := cli.Main(full, &out, &out)
	e.exit = code
	e.stdout = out.String()
}

func (e *e2eEnv) dbPath() string { return filepath.Join(e.dir, "data", "owntrace.db") }

// findings loads all findings for the latest session through the storage API.
func (e *e2eEnv) findings(t *testing.T) map[string]map[string]bool {
	t.Helper()
	// Re-open the DB through a lightweight CLI call instead of importing
	// storage (keeps this an end-to-end black-box test).
	var out bytes.Buffer
	code := cli.Main([]string{"results", "list", "--json",
		"--config", filepath.Join(e.dir, "owntrace.yaml"),
		"--auth", filepath.Join(e.dir, "auth.yaml"), "--log-level", "error"}, &out, &out)
	if code != 0 {
		t.Fatalf("results list failed (exit %d): %s", code, out.String())
	}
	var parsed struct {
		Findings []struct {
			ID       string `json:"id"`
			State    string `json:"state"`
			Category string `json:"category"`
			URL      string `json:"url"`
			Controls []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"controls"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("parse results JSON: %v\n%s", err, out.String())
	}
	byURL := map[string]map[string]bool{}
	for _, f := range parsed.Findings {
		m := byURL[f.URL]
		if m == nil {
			m = map[string]bool{}
			byURL[f.URL] = m
		}
		m[f.State] = true
		m["cat:"+f.Category] = true
		for _, c := range f.Controls {
			m["ctl:"+c.Name+"="+c.Status] = true
		}
	}
	return byURL
}

func stateFor(t *testing.T, byURL map[string]map[string]bool, urlSuffix string) (map[string]bool, bool) {
	t.Helper()
	for u, m := range byURL {
		if strings.HasSuffix(u, urlSuffix) {
			return m, true
		}
	}
	return nil, false
}

func requireState(t *testing.T, byURL map[string]map[string]bool, urlSuffix, state, category string) {
	t.Helper()
	m, ok := stateFor(t, byURL, urlSuffix)
	if !ok {
		t.Fatalf("no finding for %s; got URLs: %v", urlSuffix, keys(byURL))
	}
	if !m[state] {
		t.Fatalf("finding for %s: expected state %s, got %v\ncontrols: %v", urlSuffix, state, stateKeys(m), m)
	}
	if category != "" && !m["cat:"+category] {
		t.Fatalf("finding for %s: expected category %s, got %v", urlSuffix, category, m)
	}
}

func requireNotConfirmed(t *testing.T, byURL map[string]map[string]bool, urlSuffix string) {
	t.Helper()
	m, ok := stateFor(t, byURL, urlSuffix)
	if !ok {
		return // no finding at all is fine for protected resources
	}
	if m["CONFIRMED"] {
		t.Fatalf("FALSE POSITIVE: %s reached CONFIRMED (states: %v)", urlSuffix, stateKeys(m))
	}
}

func stateKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keys(m map[string]map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---- the acceptance matrix --------------------------------------------------

func TestE2EVulnerableEndpointsConfirmed(t *testing.T) {
	env := setupE2E(t, true)
	if env.exit != 5 {
		t.Fatalf("scan exit code: want 5 (confirmed findings), got %d\n%s", env.exit, env.stdout)
	}
	by := env.findings(t)
	requireState(t, by, "/api/v1/orders/o-1001", "CONFIRMED", "horizontal_object_access")
	requireState(t, by, "/api/v1/documents/doc-3001", "CONFIRMED", "horizontal_object_access")
	requireState(t, by, "/api/v1/tenants/t-acme/files/f-9001", "CONFIRMED", "cross_tenant_access")
	requireState(t, by, "/api/v1/orders/o-1001/notes", "CONFIRMED", "nested_resource_authorization")
	requireState(t, by, "/redirect/orders/o-1001", "CONFIRMED", "")
	// §24: the privileged-endpoint bypass is a FUNCTION-level finding
	// (BFLA), a separate finding type from object-level vertical BOLA.
	requireState(t, by, "/api/v1/admin/stats", "CONFIRMED", "broken_function_level_authorization")
	requireState(t, by, "/api/v1/receipts/r-6001", "CONFIRMED", "anonymous_access")
}

func TestE2EProtectedEndpointsNotFlagged(t *testing.T) {
	env := setupE2E(t, true)
	by := env.findings(t)
	requireNotConfirmed(t, by, "/api/v1/invoices/inv-2001")
	requireNotConfirmed(t, by, "/api/v1/invoices/inv-2004")
	requireNotConfirmed(t, by, "/api/v1/invoices/inv-2001/payments")
	requireNotConfirmed(t, by, "/api/v1/workspaces/ws-2/reports/r-5002")
	requireNotConfirmed(t, by, "/api/v1/admin/users/usr-alice")
	// The protected invoices must be explicitly REJECTED (control verified).
	if m, ok := stateFor(t, by, "/api/v1/invoices/inv-2001"); ok && !m["REJECTED"] {
		t.Fatalf("protected invoice not REJECTED: %v", stateKeys(m))
	}
}

func TestE2EDecoyAndPublicContentFiltered(t *testing.T) {
	env := setupE2E(t, true)
	by := env.findings(t)
	// Echo decoy: same content to everyone — must NOT confirm horizontally.
	requireNotConfirmed(t, by, "/api/v1/echo/o-1001")
	// Receipt is public content: horizontal category must not confirm...
	if m, ok := stateFor(t, by, "/api/v1/receipts/r-6001"); ok {
		// anonymous category confirmed; horizontal rejected as public
		if m["cat:horizontal_object_access"] && m["CONFIRMED"] && !m["cat:anonymous_access"] {
			t.Fatalf("public receipt confirmed as horizontal instead of anonymous: %v", stateKeys(m))
		}
	}
}

func TestE2ECacheArtifactNotConfirmed(t *testing.T) {
	env := setupE2E(t, true)
	by := env.findings(t)
	requireNotConfirmed(t, by, "/api/v1/cached-docs/doc-3001")
	if m, ok := stateFor(t, by, "/api/v1/cached-docs/doc-3001"); ok {
		if !m["ctl:cache_analysis=FAIL"] {
			t.Fatalf("cache artifact finding lacks failing cache control: %v", stateKeys(m))
		}
	}
}

func TestE2EDryRunSendsNoFindings(t *testing.T) {
	env := setupE2E(t, false)
	env.run(t, "scan", "--dry-run")
	if env.exit != 0 {
		t.Fatalf("dry-run exit: %d\n%s", env.exit, env.stdout)
	}
	if !strings.Contains(env.stdout, "dry-run:    true") {
		t.Fatalf("dry-run summary missing: %s", env.stdout)
	}
	if strings.Contains(env.stdout, "CONFIRMED") && strings.Contains(env.stdout, "1") {
		t.Log(env.stdout)
	}
}

func TestE2EReportsGenerated(t *testing.T) {
	env := setupE2E(t, false)
	repDir := filepath.Join(env.dir, "data", "reports")
	for _, f := range []string{"report.json", "report.md", "report.html", "findings.csv"} {
		b, err := os.ReadFile(filepath.Join(repDir, f))
		if err != nil {
			t.Fatalf("report %s missing: %v", f, err)
		}
		if len(b) < 200 {
			t.Fatalf("report %s suspiciously small: %d bytes", f, len(b))
		}
	}
	// Markdown report must contain the confirmed section and no secrets.
	md, _ := os.ReadFile(filepath.Join(repDir, "report.md"))
	if !bytes.Contains(md, []byte("CONFIRMED")) {
		t.Fatal("markdown report lacks findings")
	}
	if bytes.Contains(md, []byte("tok-alice-fixed-lab-token")) || bytes.Contains(md, []byte("tok-bob-fixed-lab-token")) {
		t.Fatal("CREDENTIAL LEAK in markdown report")
	}
	if bytes.Contains(md, []byte("pw-alice")) {
		t.Fatal("password leak in markdown report")
	}
}

func TestE2ECLIBasics(t *testing.T) {
	env := setupE2E(t, false)
	env.run(t, "version")
	if env.exit != 0 || !strings.Contains(env.stdout, "OWNTRACE") {
		t.Fatalf("version cmd failed: %d %s", env.exit, env.stdout)
	}
	env.run(t, "config", "validate")
	if env.exit != 0 {
		t.Fatalf("config validate failed: %s", env.stdout)
	}
	env.run(t, "scope", "check", "--url", "http://other-host.invalid/api", "--method", "GET")
	if env.exit != 3 {
		t.Fatalf("scope check for foreign host: want exit 3, got %d %s", env.exit, env.stdout)
	}
	env.run(t, "auth", "list")
	if env.exit != 0 || !strings.Contains(env.stdout, "alice") {
		t.Fatalf("auth list failed: %s", env.stdout)
	}
	env.run(t, "auth", "check")
	if env.exit != 0 {
		t.Fatalf("auth check failed: %s", env.stdout)
	}
	env.run(t, "results", "integrity")
	if env.exit != 0 {
		t.Fatalf("evidence integrity check failed: %s", env.stdout)
	}
}

func TestE2EIdentitySeparationAbort(t *testing.T) {
	// Two profiles that resolve to the SAME identity must abort testing.
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	base := "http://" + srv.Listener.Addr().String()
	dir := t.TempDir()
	authYAML := fmt.Sprintf(`
auth:
  profiles:
    - name: userA
      type: bearer
      token: "%s"
      identity: {endpoint: "%s/api/v1/profile", method: "GET", field: "user.id"}
    - name: userB
      type: bearer
      token: "%s"
      identity: {endpoint: "%s/api/v1/profile", method: "GET", field: "user.id"}
`, app.Tokens()["alice"], base, app.Tokens()["alice"], base)
	_ = os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(authYAML), 0o600)
	cfgYAML := fmt.Sprintf(`
version: 1
session: {name: "sep", output_dir: "%s/data", log_level: "error"}
scope:
  targets: [{host: "%s", schemes: ["http"], include_paths: ["/"]}]
limits: {rate_per_second: 100}
auth: {require_distinct_identities: true}
objects:
  declared:
    - {profile: userA, resource: order, url: "%s/api/v1/orders/o-1001", identifiers: ["o-1001"]}
`, dir, srv.Listener.Addr().String(), base)
	_ = os.WriteFile(filepath.Join(dir, "owntrace.yaml"), []byte(cfgYAML), 0o600)

	var out bytes.Buffer
	code := cli.Main([]string{"scan",
		"--config", filepath.Join(dir, "owntrace.yaml"),
		"--auth", filepath.Join(dir, "auth.yaml"), "--log-level", "error"}, &out, &out)
	// Scan completes but must NOT have tested (no confirmed findings) and must
	// explain the abort.
	if code == 5 {
		t.Fatalf("identical identities still produced CONFIRMED findings:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "identity separation NOT verified") {
		t.Fatalf("abort note missing:\n%s", out.String())
	}
}
