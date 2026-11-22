package scan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/cli"
)

// TestE2EScanTargetFlagDryRun proves the canonical primary command from the
// CLI specification: `owntrace scan -u URL --dry-run` starts the full
// orchestrated workflow (discovery → ownership mapping → plan) with no
// verification requests sent.
func TestE2EScanTargetFlagDryRun(t *testing.T) {
	env := setupE2E(t, false)
	env.run(t, "scan", "-u", env.srv.URL, "--dry-run")
	if env.exit != 0 {
		t.Fatalf("scan -u --dry-run exit: want 0, got %d\n%s", env.exit, env.stdout)
	}
	for _, want := range []string{"dry-run:    true", "would test", "Identity separation verified: true"} {
		if !strings.Contains(env.stdout, want) {
			t.Fatalf("scan -u output missing %q:\n%s", want, env.stdout)
		}
	}
}

// TestE2EProfileFilterDryRun proves --profile restricts the scan to the
// named profiles; unknown profiles are refused, and a subset that breaks
// config consistency (declared objects of excluded profiles) is rejected by
// re-validation with an actionable error.
func TestE2EProfileFilterDryRun(t *testing.T) {
	env := setupE2E(t, false)
	env.run(t, "scan", "--profile", "alice", "--profile", "bob", "--dry-run")
	if env.exit != 0 {
		t.Fatalf("profile-filtered scan exit: %d\n%s", env.exit, env.stdout)
	}
	if !strings.Contains(env.stdout, "profiles:   alice, bob") {
		t.Fatalf("profile filter not applied:\n%s", env.stdout)
	}

	env.run(t, "scan", "--profile", "nobody", "--dry-run")
	if env.exit == 0 {
		t.Fatal("unknown --profile must be refused")
	}
	if !strings.Contains(env.stdout, "no such authentication profile") {
		t.Fatalf("unknown profile error not actionable:\n%s", env.stdout)
	}

	// alice alone excludes bob, but bob owns declared objects — the merged
	// config is invalid and the error names the exact conflict.
	env.run(t, "scan", "--profile", "alice", "--dry-run")
	if env.exit == 0 {
		t.Fatal("profile subset breaking declared-object references must be refused")
	}
	if !strings.Contains(env.stdout, "profile \"bob\" is not defined in auth") {
		t.Fatalf("consistency error not actionable:\n%s", env.stdout)
	}
}

// TestE2ENoDiscoverRejectsMissingInventory proves §5: --no-discover refuses
// to scan when no previous completed inventory exists (fresh output dir).
func TestE2ENoDiscoverRejectsMissingInventory(t *testing.T) {
	env := setupE2E(t, false)
	// A fresh output directory = an empty database = no stored inventory.
	freshData := filepath.Join(env.dir, "data-fresh")
	if err := os.MkdirAll(freshData, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(env.dir, "owntrace-fresh.yaml")
	raw, err := os.ReadFile(filepath.Join(env.dir, "owntrace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	modified := strings.Replace(string(raw), filepath.Join(env.dir, "data"), freshData, 1)
	if err := os.WriteFile(cfgPath, []byte(modified), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	code := cli.Main([]string{"scan", "--no-discover", "--dry-run",
		"--config", cfgPath, "--auth", filepath.Join(env.dir, "auth.yaml"), "--log-level", "error"},
		&out, &out)
	if code == 0 {
		t.Fatalf("--no-discover with no inventory must fail\n%s", out.String())
	}
	if !strings.Contains(out.String(), "no previous completed session inventory") {
		t.Fatalf("rejection reason not actionable:\n%s", out.String())
	}
}

// TestE2ENoDiscoverReusesInventory proves --no-discover reuses the most
// recent completed session's endpoints (scope-compatible only) instead of
// re-running discovery.
func TestE2ENoDiscoverReusesInventory(t *testing.T) {
	env := setupE2E(t, false) // setupE2E completes a full scan → inventory exists
	env.run(t, "scan", "--no-discover", "--dry-run")
	if env.exit != 0 {
		t.Fatalf("--no-discover after a completed scan must work: %d\n%s", env.exit, env.stdout)
	}
	if !strings.Contains(env.stdout, "reused") {
		t.Fatalf("inventory reuse not reported:\n%s", env.stdout)
	}
}
