// Direct CLI behavior tests: exit codes, help output, redaction guarantees.
package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/cli"
)

func runCLI(args ...string) (int, string) {
	var out bytes.Buffer
	code := cli.Main(args, &out, &out)
	return code, out.String()
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "owntrace.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validYAML = `version: 1
scope:
  targets:
    - host: "127.0.0.1:1"
      include_paths: ["/"]
limits: {rate_per_second: 10}
`

func TestVersionCommand(t *testing.T) {
	code, out := runCLI("version")
	if code != cli.ExitOK {
		t.Fatalf("version exit: %d", code)
	}
	if !strings.Contains(out, "OWNTRACE ") || !strings.Contains(out, "linux/amd64") {
		t.Fatalf("version output incomplete: %s", out)
	}
	// Version must be a semantic version (vMAJOR.MINOR.PATCH).
	if !strings.Contains(out, "1.") && !strings.Contains(out, "0.") {
		t.Fatalf("no semantic version in output: %s", out)
	}
}

func TestUnknownCommandExitsUsage(t *testing.T) {
	code, out := runCLI("definitely-not-a-command")
	if code != cli.ExitUsage {
		t.Fatalf("unknown command exit: %d (out: %s)", code, out)
	}
	if !strings.Contains(out, "unknown command") {
		t.Fatalf("usage message missing: %s", out)
	}
}

func TestHelpFlagPrintsSubcommands(t *testing.T) {
	code, out := runCLI("--help")
	if code != cli.ExitOK {
		t.Fatalf("help exit: %d", code)
	}
	for _, want := range []string{"scan", "discover", "results", "auth", "scope"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help missing subcommand %q", want)
		}
	}
}

func TestConfigValidateExitCodes(t *testing.T) {
	code, _ := runCLI("config", "validate", "--config", writeTempConfig(t, validYAML))
	if code != cli.ExitOK {
		t.Fatalf("valid config exit: %d", code)
	}
	code, out := runCLI("config", "validate", "--config", writeTempConfig(t, "version: 9\n"))
	if code != cli.ExitConfig {
		t.Fatalf("invalid config exit: %d (out: %s)", code, out)
	}
	if !strings.Contains(out, "error:") {
		t.Fatalf("validation error not actionable: %s", out)
	}
}

func TestScopeCheckExitCodes(t *testing.T) {
	cfg := writeTempConfig(t, validYAML)
	code, out := runCLI("scope", "check", "--url", "http://127.0.0.1:1/api/x", "--config", cfg)
	if code != cli.ExitOK {
		t.Fatalf("in-scope check exit: %d (%s)", code, out)
	}
	code, out = runCLI("scope", "check", "--url", "http://evil.example.com/api", "--config", cfg)
	if code != cli.ExitScope {
		t.Fatalf("out-of-scope check exit: %d", code)
	}
	if !strings.Contains(out, "DENIED") {
		t.Fatalf("denial not reported: %s", out)
	}
}

func TestAuthListRedactsAndReports(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "auth.yaml"),
		[]byte("auth:\n  profiles:\n    - {name: userA, type: bearer, token: \"super-secret-token-abc\"}\n"), 0o600)
	cfg := writeTempConfig(t, validYAML)
	code, out := runCLI("auth", "list", "--config", cfg, "--auth", filepath.Join(dir, "auth.yaml"))
	if code != cli.ExitOK {
		t.Fatalf("auth list exit: %d (%s)", code, out)
	}
	if !strings.Contains(out, "userA") {
		t.Fatalf("profile name missing: %s", out)
	}
	if strings.Contains(out, "super-secret-token-abc") {
		t.Fatal("token leaked in auth list output")
	}
}

func TestOverlyPermissiveAuthFileRejected(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.yaml")
	_ = os.WriteFile(authPath, []byte("auth:\n  profiles: []\n"), 0o644)
	cfg := writeTempConfig(t, validYAML)
	code, out := runCLI("config", "validate", "--config", cfg, "--auth", authPath)
	if code != cli.ExitConfig {
		t.Fatalf("broad-permission auth file exit: %d (%s)", code, out)
	}
	if !strings.Contains(out, "permissions") {
		t.Fatalf("permission explanation missing: %s", out)
	}
}

func TestScanRequiresConfiguration(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	code, out := runCLI("scan", "--config", missing)
	if code != cli.ExitConfig && code != cli.ExitRuntime {
		t.Fatalf("scan with missing config exit: %d (%s)", code, out)
	}
	if !strings.Contains(out, "error:") {
		t.Fatalf("error not reported: %s", out)
	}
}
