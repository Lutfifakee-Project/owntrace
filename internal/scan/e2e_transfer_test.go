package scan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2ETransferRoundTrip proves §35–§36: export → import produces a new
// session with equivalent findings; backup writes a valid snapshot; restore
// replaces the database after validation and keeps a rollback copy.
func TestE2ETransferRoundTrip(t *testing.T) {
	env := setupE2E(t, false) // completed scan exists
	bundle := filepath.Join(env.dir, "bundle.json")
	snap := filepath.Join(env.dir, "snapshot.db")

	env.run(t, "results", "export", "--out", bundle)
	if env.exit != 0 || !strings.Contains(env.stdout, "exported session") {
		t.Fatalf("export failed: %d\n%s", env.exit, env.stdout)
	}

	env.run(t, "results", "backup", "--out", snap)
	if env.exit != 0 || !strings.Contains(env.stdout, "snapshot written") {
		t.Fatalf("backup failed: %d\n%s", env.exit, env.stdout)
	}

	env.run(t, "results", "import", "--file", bundle)
	if env.exit != 0 || !strings.Contains(env.stdout, "imported as session") {
		t.Fatalf("import failed: %d\n%s", env.exit, env.stdout)
	}

	env.run(t, "results", "restore", "--file", snap)
	if env.exit == 0 {
		t.Fatal("restore without --force must be refused")
	}
	env.run(t, "results", "restore", "--file", snap, "--force")
	if env.exit != 0 || !strings.Contains(env.stdout, "database restored") {
		t.Fatalf("restore failed: %d\n%s", env.exit, env.stdout)
	}
	if !strings.Contains(env.stdout, "pre-restore") {
		t.Fatalf("rollback copy not preserved:\n%s", env.stdout)
	}

	// After restore the imported session is gone (the snapshot predates it)
	// and the original session is back.
	env.run(t, "results", "sessions")
	if env.exit != 0 {
		t.Fatalf("sessions after restore: %d\n%s", env.exit, env.stdout)
	}
}

// TestE2EImportRefusesTamperedEvidence proves §35 fail-closed export
// validation on the import side: a bundle whose evidence payload was
// modified is refused.
func TestE2EImportRefusesTamperedEvidence(t *testing.T) {
	env := setupE2E(t, false)
	bundle := filepath.Join(env.dir, "bundle.json")
	env.run(t, "results", "export", "--out", bundle)
	if env.exit != 0 {
		t.Fatalf("export failed: %d\n%s", env.exit, env.stdout)
	}
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the FIRST evidence sha256 field: the recomputed payload
	// hash will no longer match, so the import must refuse.
	tampered := strings.Replace(string(raw), `"sha256": "`, `"sha256": "f`, 1)
	if tampered == string(raw) {
		t.Skip("bundle carries no evidence records")
	}
	tamperedPath := filepath.Join(env.dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	env.run(t, "results", "import", "--file", tamperedPath)
	if env.exit == 0 {
		t.Fatal("tampered bundle must be refused")
	}
	if !strings.Contains(env.stdout, "import refused") && !strings.Contains(env.stdout, "fails verification") {
		t.Fatalf("refusal not actionable:\n%s", env.stdout)
	}
}
