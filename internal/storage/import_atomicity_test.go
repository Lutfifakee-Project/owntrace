package storage

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
)

// buildSeededDB opens a DB and stores one completed session with a finding
// and two hash-chained evidence records (the pre-existing trusted state).
func buildSeededDB(t *testing.T, path string) *DB {
	t.Helper()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := db.BeginSession("seed", "{}")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	f := &finding.Finding{
		ID: "F-SEED-1", SessionID: sid, Category: finding.CatHorizontal, State: finding.StateConfirmed,
		Title: "seed", Method: "GET", URL: "https://t.example/x", Identifier: "x",
		CreatedAt: now, UpdatedAt: now,
	}
	f.ApplyDefaults()
	if err := db.SaveFinding(f); err != nil {
		t.Fatal(err)
	}
	makeEv := func(id, title string) *evidence.Record {
		prev, _ := db.LastEvidenceHash(sid)
		rec, berr := evidence.Build(id, "", sid, evidence.KindVerification, title,
			map[string]string{"title": title})
		if berr != nil {
			t.Fatal(berr)
		}
		rec.PrevSHA256 = prev
		return rec
	}
	if err := db.SaveEvidence(makeEv("EV-T-000001", "seed evidence one")); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveEvidence(makeEv("EV-T-000002", "seed evidence two")); err != nil {
		t.Fatal(err)
	}
	return db
}

// TestImportBundleTamperIsAtomic proves BLOCKER-1 properties 4–5:
//  1. a bundle whose evidence fails verification is refused wholesale —
//     NO partial session, findings or evidence rows are inserted;
//  2. the pre-existing sessions, records and evidence chain (including the
//     trusted per-session head) remain exactly consistent afterwards.
func TestImportBundleTamperIsAtomic(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	targetDB := buildSeededDB(t, target)

	// Build a valid bundle from a source database, then tamper with one
	// evidence payload INSIDE the bundle JSON.
	srcPath := filepath.Join(dir, "src.db")
	srcDB := buildSeededDB(t, srcPath)
	latest, err := srcDB.LatestSessionID()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := srcDB.ExportBundle(latest)
	if err != nil {
		t.Fatal(err)
	}
	if err := srcDB.Close(); err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(bundle), `"kind": "verification_step"`, `"kind": "verification_step TAMPERED"`, 1)
	if tampered == string(bundle) {
		t.Fatal("tamper did not change the bundle (fixture drift)")
	}

	// Pre-state snapshot of the target.
	sessionsBefore, err := targetDB.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	findingsBefore, err := targetDB.ListFindings(sessionsBefore[0].ID, "")
	if err != nil {
		t.Fatal(err)
	}
	headBefore, err := targetDB.LastEvidenceHash(sessionsBefore[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	// The refused import.
	_, _, err = targetDB.ImportBundle([]byte(tampered))
	if err == nil {
		t.Fatal("tampered bundle was imported — SECURITY REGRESSION")
	}
	// The refusal must be integrity/verification-based (digest mismatch or
	// payload-hash failure) — never a partial or best-effort import.
	if !strings.Contains(err.Error(), "verification") && !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("refusal reason not integrity/verification-based: %v", err)
	}

	// Property 4: NOTHING was inserted (no partial trust).
	sessionsAfter, err := targetDB.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessionsAfter) != len(sessionsBefore) {
		t.Fatalf("session count changed after refusal: before=%d after=%d", len(sessionsBefore), len(sessionsAfter))
	}
	for _, sess := range sessionsAfter {
		if strings.HasPrefix(sess.ID, "IMP-") {
			t.Fatalf("partial import session left behind: %s", sess.ID)
		}
	}
	findingsAfter, err := targetDB.ListFindings(sessionsAfter[0].ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsAfter) != len(findingsBefore) || findingsAfter[0].ID != findingsBefore[0].ID {
		t.Fatalf("existing findings mutated by refused import")
	}

	// Property 5: chain head and every stored record still verify.
	headAfter, err := targetDB.LastEvidenceHash(sessionsAfter[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if headAfter != headBefore {
		t.Fatalf("evidence chain head changed after refused import: %q -> %q", headBefore, headAfter)
	}
	checked, failed, errs, verr := targetDB.VerifyAllEvidence()
	if verr != nil {
		t.Fatalf("VerifyAllEvidence: %v", verr)
	}
	if failed != 0 || checked < 2 {
		t.Fatalf("stored evidence no longer consistent after refusal: checked=%d failed=%d (%v)", checked, failed, errs)
	}
	if err := targetDB.Close(); err != nil {
		t.Fatal(err)
	}
}
