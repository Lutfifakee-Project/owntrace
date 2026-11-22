package storage

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/finding"
)

// TestEnrichedFindingRoundTrip proves the triage enrichment (severity source,
// CWE/OWASP, triage notes, accepted-risk, suppression) survives a full
// persistence cycle including the schema v3 migration on an existing DB.
func TestEnrichedFindingRoundTrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	sid, err := db.BeginSession("s1", "{}")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	now := time.Now().UTC()
	f := &finding.Finding{
		ID: "F-RT-1", SessionID: sid, Category: finding.CatBOPLA, State: finding.StateConfirmed,
		Title: "restricted property exposed", Method: "GET", URL: "https://t.example/api/doc/d-1",
		Identifier: "d-1", OwnerProfile: "alice", Requester: "bob", Confidence: 0.97,
		CreatedAt: now, UpdatedAt: now,
	}
	f.ApplyDefaults()
	_ = f.SetSeverity(finding.SevHigh)
	f.AddTriageNote("yukii", "contains salary field")
	_ = f.AcceptRisk("fix scheduled Q3", "boss")
	if err := db.SaveFinding(f); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := db.ListFindings(sid, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	g := got[0]
	if g.Severity != finding.SevHigh || g.SeveritySrc != "operator" {
		t.Errorf("severity lost: %q/%q", g.Severity, g.SeveritySrc)
	}
	if g.CWE != finding.DefaultCWE(finding.CatBOPLA) || g.OWASP != finding.DefaultOWASP(finding.CatBOPLA) {
		t.Errorf("CWE/OWASP lost: %q/%q", g.CWE, g.OWASP)
	}
	if len(g.TriageNotes) != 1 || g.TriageNotes[0].Text != "contains salary field" {
		t.Errorf("triage notes lost: %+v", g.TriageNotes)
	}
	if g.AcceptedRisk == nil || g.AcceptedRisk.Reason != "fix scheduled Q3" {
		t.Errorf("accepted risk lost: %+v", g.AcceptedRisk)
	}
	if g.IsSuppressed() {
		t.Error("unexpected suppression")
	}

	// Suppression persists and loads.
	if err := g.Suppress("duplicate of F-RT-2", "yukii"); err != nil {
		t.Fatalf("suppress: %v", err)
	}
	if err := db.SaveFinding(g); err != nil {
		t.Fatalf("save suppressed: %v", err)
	}
	got, err = db.ListFindings(sid, string(finding.StateConfirmed))
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(got) != 1 || got[0].Suppression == nil || got[0].Suppression.By != "yukii" {
		t.Fatalf("suppression not persisted: %+v", got)
	}
}

// TestMigrationV2ToV3 proves an existing v2 database upgrades in place and
// gains the enrichment columns without data loss.
func TestMigrationV2ToV3(t *testing.T) {
	dir := t.TempDir()

	// Create a v2 database by opening with the current code, then manually
	// downgrading: drop the enrichment columns via a fresh v2-shaped DB.
	db, err := Open(filepath.Join(dir, "seed.db"))
	if err != nil {
		t.Fatalf("open seed: %v", err)
	}
	_ = db.Close()

	// Simulate the v2 layout: copy the seed DB and rebuild findings without
	// the new columns (the migration must tolerate the old shape).
	legacy := filepath.Join(dir, "legacy.db")
	ldb, err := Open(legacy)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	mid, err := ldb.BeginSession("mig", "{}")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	// Drop and recreate findings in the v2 shape (no enrichment columns).
	for _, stmt := range []string{
		`DROP TABLE findings`,
		`CREATE TABLE findings (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL REFERENCES sessions(id),
			category TEXT NOT NULL,
			state TEXT NOT NULL,
			title TEXT NOT NULL,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			endpoint_id TEXT,
			resource TEXT,
			identifier TEXT,
			owner_profile TEXT,
			requester TEXT,
			owner_state TEXT,
			confidence REAL NOT NULL DEFAULT 0,
			reason TEXT NOT NULL DEFAULT '',
			remediation TEXT,
			controls_json TEXT NOT NULL DEFAULT '[]',
			transitions_json TEXT NOT NULL DEFAULT '[]',
			evidence_ids_json TEXT NOT NULL DEFAULT '[]',
			reproduction_json TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`DELETE FROM schema_migrations WHERE version >= 3`,
	} {
		if _, err := ldb.db.Exec(stmt); err != nil {
			t.Fatalf("legacy shape %q: %v", stmt, err)
		}
	}
	if err := ldb.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	// Reopen: the migration must add the missing columns.
	re, err := Open(legacy)
	if err != nil {
		t.Fatalf("reopen (migration v3): %v", err)
	}
	defer re.Close()
	now := time.Now().UTC()
	f := &finding.Finding{
		ID: "F-MIG-1", SessionID: mid, Category: finding.CatBFLA, State: finding.StateSuspected,
		Title: "t", Method: "GET", URL: "https://t.example/admin", Identifier: "x",
		CreatedAt: now, UpdatedAt: now,
	}
	f.ApplyDefaults()
	if err := re.SaveFinding(f); err != nil {
		t.Fatalf("save after migration: %v", err)
	}
	got, err := re.ListFindings(mid, "")
	if err != nil {
		t.Fatalf("list after migration: %v", err)
	}
	if len(got) != 1 || got[0].Severity != finding.DefaultSeverity(finding.CatBFLA) {
		t.Fatalf("migration round-trip failed: %+v", got)
	}
}

// TestEvidenceSeqSurvivesReopen is the regression test for the evidence-ID
// collision defect: a NEW engine on an EXISTING database must continue the
// persisted sequence, never restart at 1 (which collided with stored rows).
func TestEvidenceSeqSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seq.db")
	db1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Seed two stored evidence rows: the persisted counter is recovered from
	// rows, so the reopen test needs real history (an empty table may
	// legitimately restart at 1 — there is nothing to collide with).
	for i, id := range []string{"EV-20261121-000001", "EV-20261121-000002"} {
		if _, err := db1.db.Exec(`INSERT INTO evidence (id, finding_id, session_id, kind, title, data_json, sha256, prev_sha256, created_at)
			VALUES (?, 'F-1', 'S-1', 'verification_step', 'seed', '{}', ?, '', ?)`, id, strings.Repeat("a", 64), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("seed evidence %s: %v", id, err)
		}
		_ = i
	}
	// Issue two sequence numbers and persist evidence with them — every
	// issued number is stored with its evidence record in real runs.
	first := db1.NextEvidenceSeq()
	second := db1.NextEvidenceSeq()
	if second <= first {
		t.Fatalf("in-process seq not monotonic: %d then %d", first, second)
	}
	for i, seq := range []int{first, second} {
		id := fmt.Sprintf("EV-20261121-%06d", seq)
		if _, err := db1.db.Exec(`INSERT INTO evidence (id, finding_id, session_id, kind, title, data_json, sha256, prev_sha256, created_at)
			VALUES (?, 'F-1', 'S-1', 'verification_step', 'issued', '{}', ?, '', ?)`, id, strings.Repeat("b", 64), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("persist issued evidence %s: %v", id, err)
		}
		_ = i
	}
	if err := db1.Close(); err != nil {
		t.Fatal(err)
	}

	db2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	third := db2.NextEvidenceSeq()
	if third <= second {
		t.Fatalf("reopened DB restarted the evidence sequence: persisted %d, next %d", second, third)
	}
}
