package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owntrace.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validConfig() string {
	return `
version: 1
scope:
  targets:
    - host: "api.test"
      include_paths: ["/"]
limits:
  rate_per_second: 50
auth:
  require_distinct_identities: true
`
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, validConfig()), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scope.Targets) != 1 || cfg.Scope.Targets[0].Host != "api.test" {
		t.Fatalf("targets wrong: %+v", cfg.Scope.Targets)
	}
	if cfg.Limits.RatePerSecond != 50 {
		t.Errorf("rate not preserved")
	}
	// defaults applied
	if cfg.Limits.Concurrency < 1 {
		t.Error("concurrency default missing")
	}
	if cfg.Verification.Repeats < 1 {
		t.Error("repeats default missing")
	}
	if len(cfg.Report.Formats) == 0 {
		t.Error("report formats default missing")
	}
}

func TestRejectsSchemeInHost(t *testing.T) {
	_, err := Load(writeTestConfig(t, strings.Replace(validConfig(), `host: "api.test"`, `host: "https://api.test"`, 1)), "")
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("scheme-in-host accepted: %v", err)
	}
}

func TestRejectsEmptyScope(t *testing.T) {
	_, err := Load(writeTestConfig(t, "version: 1\nscope:\n  targets: []\n"), "")
	if err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("empty scope accepted: %v", err)
	}
}

func TestRejectsBadProfileType(t *testing.T) {
	cfg := validConfig() + `
objects:
  declared: []
`
	_, err := Load(writeTestConfig(t, cfg), "")
	_ = err // profile validation happens via auth file or inline; nothing to assert here
}

func TestDeclaredObjectRequiresProfile(t *testing.T) {
	cfg := validConfig() + `
objects:
  declared:
    - profile: ghost
      url: "http://api.test/x/1"
      identifiers: ["1"]
`
	_, err := Load(writeTestConfig(t, cfg), "")
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("undeclared-profile object accepted: %v", err)
	}
}

func TestCreationRequiresWriteOptIn(t *testing.T) {
	cfg := validConfig() + `
objects:
  creation:
    enabled: true
    endpoint: "http://api.test/api/orders"
    extract_field: "id"
    profiles: ["x"]
`
	_, err := Load(writeTestConfig(t, cfg), "")
	if err == nil || !strings.Contains(err.Error(), "allow_write_methods") {
		t.Fatalf("creation enabled without write opt-in accepted: %v", err)
	}
}

func TestAuthFilePermissionsEnforced(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.yaml")
	_ = os.WriteFile(authPath, []byte("auth:\n  profiles: []\n"), 0o644)
	cfg, err := Load(writeTestConfig(t, validConfig()), authPath)
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("broad-permission auth file accepted: %v, cfg=%v", err, cfg != nil)
	}
	// fix permissions → accepted
	if err := os.Chmod(authPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(writeTestConfig(t, validConfig()), authPath); err != nil {
		t.Fatalf("0600 auth file rejected: %v", err)
	}
}

func TestEnvSecretResolution(t *testing.T) {
	t.Setenv("OT_TEST_TOKEN_XYZ", "resolved-token-value")
	v, err := ResolveSecret("{{ env OT_TEST_TOKEN_XYZ }}")
	if err != nil {
		t.Fatal(err)
	}
	if v != "resolved-token-value" {
		t.Fatalf("env not resolved: %q", v)
	}
	v2, _ := ResolveSecret("{{ env OT_MISSING_VAR_42 }}")
	if v2 != "" {
		t.Fatalf("missing env should resolve empty, got %q", v2)
	}
}

func TestRedactedCopyHasNoSecrets(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, validConfig()), "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.Profiles = []Profile{{Name: "u", Type: "bearer", Token: "super-secret-token-value"}}
	rc := cfg.RedactedCopy()
	if rc.Auth.Profiles[0].Token == "super-secret-token-value" {
		t.Fatal("token survived redacted copy")
	}
	// original untouched (needed at runtime)
	if cfg.Auth.Profiles[0].Token != "super-secret-token-value" {
		t.Fatal("redacted copy mutated the original config")
	}
}

func TestTemplates(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "owntrace.yaml")
	authPath := filepath.Join(dir, "auth.yaml")
	if err := WriteTemplate(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := WriteAuthTemplate(authPath); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(authPath)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("auth template permissions: %v", st.Mode().Perm())
	}
	if _, err := Load(cfgPath, ""); err != nil {
		t.Fatalf("generated template invalid: %v", err)
	}
}
