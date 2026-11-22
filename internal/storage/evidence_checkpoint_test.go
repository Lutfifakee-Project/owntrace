package storage

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
)

// seedChain opens a DB and stores a session with three hash-chained evidence
// records; returns the DB and the session ID.
func seedChain(t *testing.T, path string) (*DB, string) {
	t.Helper()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := db.BeginSession("checkpoint-seed", "{}")
	if err != nil {
		t.Fatal(err)
	}
	for i, title := range []string{"one", "two", "three"} {
		prev, _ := db.LastEvidenceHash(sid)
		rec, berr := evidence.Build("EV-C-00000"+string(rune('1'+i)), "", sid,
			evidence.KindVerification, title, map[string]string{"n": title})
		if berr != nil {
			t.Fatal(berr)
		}
		rec.PrevSHA256 = prev
		if err := db.SaveEvidence(rec); err != nil {
			t.Fatal(err)
		}
	}
	return db, sid
}

// TestEvidenceCheckpointAnchoring proves the §35 trusted-head property:
//  1. the checkpoint is stable and reports the record count;
//  2. a full-chain rewrite that recomputes every per-record hash passes
//     record verification but FAILS verification against the anchored head;
//  3. an honest database still verifies against the anchored head.
func TestEvidenceCheckpointAnchoring(t *testing.T) {
	dir := t.TempDir()

	// Honest case.
	db, sid := seedChain(t, filepath.Join(dir, "honest.db"))
	head, n, err := db.EvidenceCheckpoint(sid)
	if err != nil {
		t.Fatal(err)
	}
	if head == "" || n != 3 {
		t.Fatalf("checkpoint: head=%q records=%d", head, n)
	}
	checked, failed, err := db.VerifyAgainstHead(sid, head)
	if err != nil || failed != 0 || checked != 3 {
		t.Fatalf("honest anchored verification: checked=%d failed=%d err=%v", checked, failed, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Adversary case: rewrite every payload, recompute every per-record hash
	// and every prev-link so record verification alone passes (the §35
	// threat model: an attacker who can rewrite all records).
	db2, sid2 := seedChain(t, filepath.Join(dir, "rewritten.db"))
	origHead, _, err := db2.EvidenceCheckpoint(sid2)
	if err != nil {
		t.Fatal(err)
	}
	rows, qerr := db2.db.Query(`SELECT id, title FROM evidence WHERE session_id = ? ORDER BY created_at, id`, sid2)
	if qerr != nil {
		t.Fatal(qerr)
	}
	type row struct{ id, title string }
	var recs []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.title); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	rows.Close()
	if len(recs) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(recs))
	}
	prev := ""
	for _, r := range recs {
		rewritten, berr := evidence.Build(r.id, "", sid2, evidence.KindVerification,
			r.title, map[string]string{"n": r.title, "injected": "attacker"})
		if berr != nil {
			t.Fatal(berr)
		}
		rewritten.CreatedAt = time.Now().UTC()
		rewritten.PrevSHA256 = prev
		prev = rewritten.SHA256
		if _, uerr := db2.db.Exec(`UPDATE evidence SET data_json = ?, sha256 = ?, prev_sha256 = ? WHERE session_id = ? AND id = ?`,
			jsonOf(rewritten), rewritten.SHA256, rewritten.PrevSHA256, sid2, r.id); uerr != nil {
			t.Fatal(uerr)
		}
	}
	// The adversary also rewrites the stored session head (full control).
	if _, uerr := db2.db.Exec(`UPDATE sessions SET evidence_head = ? WHERE id = ?`, prev, sid2); uerr != nil {
		t.Fatal(uerr)
	}
	// Per-record + stored-head verification alone must PASS (that IS the threat).
	checked, failed, rerrs, verr := db2.VerifyAllEvidence()
	if verr != nil || failed != 0 {
		t.Fatalf("precondition: rewritten chain must pass record verification (checked=%d failed=%d err=%v errs=%v)", checked, failed, verr, rerrs)
	}
	// ...but the anchored checkpoint must catch the rewrite.
	_, _, aerr := db2.VerifyAgainstHead(sid2, origHead)
	if aerr == nil || !strings.Contains(aerr.Error(), "anchored head mismatch") {
		t.Fatalf("anchored verification MUST fail after full-chain rewrite: %v", aerr)
	}
	_ = sql.ErrNoRows // keep import meaningful for in-package SQL access
	if err := db2.Close(); err != nil {
		t.Fatal(err)
	}
}

// jsonOf serializes a record's data payload exactly like SaveEvidence does.
func jsonOf(r *evidence.Record) []byte {
	raw, err := evidence.CanonicalJSON(r.Data)
	if err != nil {
		panic(err)
	}
	return raw
}
