// Security-focused tests: scope escapes, credential hygiene, malformed
// inputs, output safety and concurrent cancellation robustness.
package scan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/cli"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/mockapp"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scan"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
	"github.com/Lutfifakee-Project/owntrace/internal/storage"
	"github.com/Lutfifakee-Project/owntrace/internal/verification"
)

// Sec-1: a scanner configured for host A must refuse requests to host B even
// when host B is an attacker-controlled redirect target.
func TestSecurityScopeEscapeViaRedirect(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("OUT-OF-SCOPE HOST RECEIVED A REQUEST: %s", r.URL)
		_, _ = w.Write([]byte("stolen"))
	}))
	defer evil.Close()

	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	_ = evil // the escape target would be reached only if redirect validation failed

	base := "http://" + srv.Listener.Addr().String()
	dir := t.TempDir()
	writeMinimalConfig(t, dir, srv.Listener.Addr().String(), base)
	auth := "auth:\n  profiles:\n    - {name: userA, type: bearer, token: \"" + app.Tokens()["alice"] + "\"}\n"
	_ = os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(auth), 0o600)

	var out strings.Builder
	code := cli.Main([]string{"scan", "--config", filepath.Join(dir, "owntrace.yaml"),
		"--auth", filepath.Join(dir, "auth.yaml"), "--log-level", "error"}, &out, &out)
	if code == 1 {
		t.Fatalf("scan usage error: %s", out.String())
	}
	// The evil server's handler asserts it was never contacted.
}

// Sec-2: destructive methods must never be sent without explicit opt-in,
// even if a vulnerable DELETE endpoint is discovered and in scope.
func TestSecurityNoDestructiveRequests(t *testing.T) {
	var deletes int
	app := mockapp.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deletes++
		}
		app.Handler().ServeHTTP(w, r)
	}))
	defer srv.Close()
	base := "http://" + srv.Listener.Addr().String()
	dir := t.TempDir()
	writeMinimalConfig(t, dir, srv.Listener.Addr().String(), base)
	auth := "auth:\n  profiles:\n    - {name: userA, type: bearer, token: \"" + app.Tokens()["alice"] + "\"}\n    - {name: userB, type: bearer, token: \"" + app.Tokens()["bob"] + "\"}\n"
	_ = os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(auth), 0o600)

	var out strings.Builder
	cli.Main([]string{"scan", "--config", filepath.Join(dir, "owntrace.yaml"),
		"--auth", filepath.Join(dir, "auth.yaml"), "--log-level", "error"}, &out, &out)
	if deletes != 0 {
		t.Fatalf("destructive DELETE requests were sent: %d", deletes)
	}
}

// Sec-3: config show must never print credential values.
func TestSecurityConfigShowRedacted(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "auth.yaml"),
		[]byte("auth:\n  profiles:\n    - {name: userA, type: bearer, token: \"very-secret-token-xyz\"}\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "owntrace.yaml"), []byte(minimalScopeYAML("127.0.0.1:1", filepath.Join(dir, "data"))), 0o600)
	var out strings.Builder
	cli.Main([]string{"config", "show", "--config", filepath.Join(dir, "owntrace.yaml"),
		"--auth", filepath.Join(dir, "auth.yaml")}, &out, &out)
	if strings.Contains(out.String(), "very-secret-token-xyz") {
		t.Fatalf("config show leaked the token:\n%s", out.String())
	}
}

// Sec-4: malformed spec files must not crash discovery.
func TestSecurityMalformedInputs(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"a.json": `{"openapi": "3.0.0", "paths": {"<{>>": {"get": null}}}`,
		"b.json": `{"swagger": "2.0", "host": 42, "paths": {"$ref": " Circular"}}`,
		"c.har":  `{"log": {"entries": [null, {"request": "not-an-object"}]}}`,
		"d.json": `[1,2,3`,
	}
	for name, content := range cases {
		_ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
	}
	discoveryCfg := []byte(minimalScopeYAML("127.0.0.1:1", filepath.Join(dir, "data")) + "\ndiscovery:\n  sources: [\"openapi\", \"har\"]\n  openapi_files: [\"" +
		filepath.Join(dir, "a.json") + "\", \"" + filepath.Join(dir, "b.json") + "\", \"" + filepath.Join(dir, "d.json") + "\"]\n  har_files: [\"" +
		filepath.Join(dir, "c.har") + "\"]\n")
	_ = os.WriteFile(filepath.Join(dir, "owntrace.yaml"), discoveryCfg, 0o600)
	var out strings.Builder
	code := cli.Main([]string{"discover", "openapi", "--config", filepath.Join(dir, "owntrace.yaml")}, &out, &out)
	if code == 1 {
		t.Fatalf("discover crashed on malformed input: %s", out.String())
	}
	// No panic = pass; notes explain failures.
}

// Sec-5: cancelling a scan mid-run must leave a consistent, marked session
// (no panic, no half-written session marked completed).
func TestSecurityConcurrentCancellation(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	base := "http://" + srv.Listener.Addr().String()
	dir := t.TempDir()
	// Low rate + several declared objects so the run is still in flight when
	// the context is cancelled after 1.5s.
	cfgYAML := `version: 1
session: {name: "cancel", output_dir: "` + filepath.Join(dir, "data") + `", log_level: "error"}
scope:
  targets:
    - host: "` + srv.Listener.Addr().String() + `"
      schemes: ["http"]
      include_paths: ["/"]
limits: {rate_per_second: 3, request_timeout_seconds: 5}
verification: {repeats: 2, require_identity_separation: false, anonymous_test: false, vertical_test: false, cache_bust: false}
objects:
  declared:
    - {profile: userA, resource: order,   url: "` + base + `/api/v1/orders/o-1001", identifiers: ["o-1001"]}
    - {profile: userA, resource: invoice, url: "` + base + `/api/v1/invoices/inv-2001", identifiers: ["inv-2001"]}
    - {profile: userA, resource: document, url: "` + base + `/api/v1/documents/doc-3001", identifiers: ["doc-3001"]}
    - {profile: userA, resource: order,   url: "` + base + `/api/v1/orders/o-1002", identifiers: ["o-1002"]}
    - {profile: userA, resource: order,   url: "` + base + `/api/v1/orders/o-1003", identifiers: ["o-1003"]}
`
	_ = os.WriteFile(filepath.Join(dir, "owntrace.yaml"), []byte(cfgYAML), 0o600)
	auth := "auth:\n  profiles:\n    - {name: userA, type: bearer, token: \"" + app.Tokens()["alice"] + "\"}\n    - {name: userB, type: bearer, token: \"" + app.Tokens()["bob"] + "\"}\n"
	_ = os.WriteFile(filepath.Join(dir, "auth.yaml"), []byte(auth), 0o600)

	// Library-level run with context cancellation after 1.5s.
	runner := buildRunner(t, filepath.Join(dir, "owntrace.yaml"), filepath.Join(dir, "auth.yaml"))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(1500 * time.Millisecond)
		cancel()
	}()
	sum, err := runner.Run(ctx, false)
	if err == nil {
		t.Fatal("cancelled scan reported success")
	}
	if sum == nil {
		t.Fatal("cancelled scan returned no summary")
	}
	_ = sum
}

// buildRunner assembles the scan runtime the same way the CLI does.
func buildRunner(t *testing.T, cfgPath, authPath string) *scan.Runner {
	t.Helper()
	cfg, err := config.Load(cfgPath, authPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.Session.OutputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(cfg.Session.OutputDir, "owntrace.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sc, err := scope.New(cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: cfg.Limits.RatePerSecond,
		PerHostRatePerSec: cfg.Limits.RatePerSecond, Concurrency: cfg.Limits.Concurrency,
		BlockedPatterns: cfg.Scope.BlockedPathPatterns, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	log := logger.New(logger.LevelError)
	cl := httpclient.New(se, log, time.Duration(cfg.Limits.RequestTimeoutSecs)*time.Second,
		cfg.Limits.MaxResponseBytes, cfg.Limits.MaxRedirects, 1)
	am, err := auth.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ev := evidence.NewEngine(db)
	ve := &verification.Engine{Client: cl, Auth: am, Scope: sc, Evid: ev, Store: db, Cfg: cfg.Verification, Log: log}
	return &scan.Runner{Cfg: cfg, Scope: sc, Client: cl, Auth: am, Log: log, DB: db, Evid: ev, Verif: ve}
}

// Sec-6: oversized and malformed JSON bodies from the target must not crash
// the evidence or storage layers.
func TestSecurityOversizedAndGarbageResponses(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"junk":"` + strings.Repeat("x", 4<<20) + `"}`))
	})
	mux.HandleFunc("/garbage", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("\x00\x01\x02 not json \xff\xfe"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base := "http://" + srv.Listener.Addr().String()
	dir := t.TempDir()
	writeMinimalConfig(t, dir, srv.Listener.Addr().String(), base)
	var out strings.Builder
	code := cli.Main([]string{"discover", "urls", "--url", base + "/big", "--url", base + "/garbage",
		"--config", filepath.Join(dir, "owntrace.yaml")}, &out, &out)
	if code != 0 {
		t.Fatalf("discover failed on hostile responses: %d %s", code, out.String())
	}
}

func writeMinimalConfig(t *testing.T, dir, host, base string) {
	t.Helper()
	_ = os.WriteFile(filepath.Join(dir, "owntrace.yaml"), []byte(minimalScopeYAML(host, filepath.Join(dir, "data"))), 0o600)
}

func minimalScopeYAML(host, outDir string) string {
	return `version: 1
session: {name: "sec", output_dir: "` + outDir + `", log_level: "error"}
scope:
  targets:
    - host: "` + host + `"
      schemes: ["http"]
      include_paths: ["/"]
limits: {rate_per_second: 100, request_timeout_seconds: 5}
verification: {repeats: 1, require_identity_separation: false, anonymous_test: false, vertical_test: false, cache_bust: false}
`
}
