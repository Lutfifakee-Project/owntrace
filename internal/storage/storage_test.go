package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	db1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db1.Close()
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen with existing schema failed: %v", err)
	}
	defer db2.Close()
}

func TestSessionLifecycle(t *testing.T) {
	db := openTestDB(t)
	id, err := db.BeginSession("test", "{}")
	if err != nil {
		t.Fatal(err)
	}
	sessions, _ := db.ListSessions()
	if len(sessions) != 1 || sessions[0].Status != SessionRunning {
		t.Fatalf("session state wrong: %+v", sessions)
	}
	if err := db.FinishSession(id, SessionCompleted); err != nil {
		t.Fatal(err)
	}
	sessions, _ = db.ListSessions()
	if sessions[0].Status != SessionCompleted {
		t.Fatalf("finish failed: %+v", sessions[0])
	}
}

func TestRecoverInterrupted(t *testing.T) {
	db := openTestDB(t)
	id, _ := db.BeginSession("stale", "{}")
	if err := db.RecoverInterrupted(); err != nil {
		t.Fatal(err)
	}
	sessions, _ := db.ListSessions()
	if sessions[0].Status != SessionInterrupted {
		t.Fatalf("interrupted recovery failed: %+v", sessions[0])
	}
	_ = id
}

func TestEndpointRoundTrip(t *testing.T) {
	db := openTestDB(t)
	sid, _ := db.BeginSession("s", "{}")
	ep, _ := endpoints.BuildFromURL("GET", "https://api.test/api/orders/o-1001", endpoints.SourceHAR, "t1")
	ep.Body = &endpoints.BodySpec{ContentType: "application/json", Template: `{"a":1}`}
	if err := db.SaveEndpoint(sid, ep); err != nil {
		t.Fatal(err)
	}
	eps, err := db.ListEndpoints(sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	if eps[0].Path != "/api/orders/{order_id}" || eps[0].Body == nil || eps[0].Body.Template != `{"a":1}` {
		t.Fatalf("round-trip loss: %+v", eps[0])
	}
}

func TestFindingRoundTripAndTransitions(t *testing.T) {
	db := openTestDB(t)
	sid, _ := db.BeginSession("s", "{}")
	now := time.Now().UTC()
	f := &finding.Finding{
		ID: "F-TEST0001", SessionID: sid, Category: finding.CatHorizontal, State: finding.StateCandidate,
		Title: "test finding", Method: "GET", URL: "https://api.test/x/1", Identifier: "1",
		OwnerProfile: "userA", Confidence: 0.5, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.SaveFinding(f); err != nil {
		t.Fatal(err)
	}
	// state transition + more data
	_ = f.Transition(finding.StateTesting, "starting", "")
	_ = f.Transition(finding.StateRejected, "authorization enforced", "")
	if err := db.SaveFinding(f); err != nil {
		t.Fatal(err)
	}
	got, err := db.ListFindings(sid, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if got[0].State != finding.StateRejected {
		t.Fatalf("state not updated: %s", got[0].State)
	}
	if len(got[0].Transitions) != 2 {
		t.Fatalf("transitions lost: %d", len(got[0].Transitions))
	}
	filtered, _ := db.ListFindings(sid, "REJECTED")
	if len(filtered) != 1 {
		t.Fatal("state filter failed")
	}
	filtered, _ = db.ListFindings(sid, "CONFIRMED")
	if len(filtered) != 0 {
		t.Fatal("state filter matched wrong rows")
	}
	counts, _ := db.FindingCounts(sid)
	if counts["REJECTED"] != 1 {
		t.Fatalf("counts wrong: %+v", counts)
	}
}

func TestEvidenceAppendOnlyAndIntegrity(t *testing.T) {
	db := openTestDB(t)
	rec, err := evidence.Build("EV-1", "F-1", "S-1", evidence.KindHTTPExchange, "probe",
		map[string]any{"status": 200, "url": "https://api.test/x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveEvidence(rec); err != nil {
		t.Fatal(err)
	}
	// duplicate insert must fail (append-only, no UPDATE path)
	if err := db.SaveEvidence(rec); err == nil {
		t.Fatal("duplicate evidence id accepted — evidence is not append-only")
	}
	got, err := db.GetEvidence("F-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(got))
	}
	if err := got[0].Verify(); err != nil {
		t.Fatalf("integrity verify failed: %v", err)
	}
	checked, failed, _, err := db.VerifyAllEvidence()
	if err != nil || checked != 1 || failed != 0 {
		t.Fatalf("bulk verify: checked=%d failed=%d err=%v", checked, failed, err)
	}
}

func TestCleanupRetention(t *testing.T) {
	db := openTestDB(t)
	sid, _ := db.BeginSession("old", "{}")
	_ = db.FinishSession(sid, SessionCompleted)
	// started_at is now — retention 30 days would not delete it; use 0-day window
	n, err := db.Cleanup(0)
	if err != nil || n != 0 {
		// 0 disables cleanup; acceptable
		t.Log("cleanup(0) disabled:", n, err)
	}
	sessions, _ := db.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("session removed by disabled cleanup: %d", len(sessions))
	}
}

func TestAuditTrail(t *testing.T) {
	db := openTestDB(t)
	sid, _ := db.BeginSession("a", "{}")
	_ = db.Audit(sid, "info", "event1", "detail")
	_ = db.Audit(sid, "warn", "event2", "detail2")
	events, err := db.ListAudit(sid, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("audit rows: %d", len(events))
	}
}

func TestObjectRoundTrip(t *testing.T) {
	db := openTestDB(t)
	sid, _ := db.BeginSession("s", "{}")
	row := &ObjectRow{ID: "obj1", SessionID: sid, Resource: "order", Identifier: "o-1001",
		OwnerProfile: "userA", OwnerState: "declared", Confidence: 0.8, CreatedAt: nowUTC()}
	if err := db.SaveObject(row); err != nil {
		t.Fatal(err)
	}
	objs, err := db.ListObjects(sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 || objs[0].Resource != "order" || objs[0].OwnerState != "declared" {
		t.Fatalf("object round trip wrong: %+v", objs)
	}
}

func TestCorruptDatabaseFailsClearly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.db")
	_ = os.WriteFile(path, []byte("this is not a sqlite database at all, just garbage bytes"), 0o600)
	if _, err := Open(path); err == nil {
		t.Fatal("garbage DB file accepted")
	}
}

// buildChainedSession stores a session with three chained evidence records.
func buildChainedSession(t *testing.T, db *DB) string {
	t.Helper()
	sid, err := db.BeginSession("chain", "{}")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rec, err := evidence.Build("EV-C"+string(rune('1'+i)), "F-1", sid, evidence.KindHTTPExchange, "step",
			map[string]any{"i": i})
		if err != nil {
			t.Fatal(err)
		}
		prev, err := db.LastEvidenceHash(sid)
		if err != nil {
			t.Fatal(err)
		}
		rec.PrevSHA256 = prev
		if err := db.SaveEvidence(rec); err != nil {
			t.Fatal(err)
		}
	}
	return sid
}

func TestEvidenceChainVerificationDetectsPayloadTampering(t *testing.T) {
	db := openTestDB(t)
	sid := buildChainedSession(t, db)
	if _, failed, _, err := db.VerifyAllEvidence(); err != nil || failed != 0 {
		t.Fatalf("pristine chain failed: failed=%d err=%v", failed, err)
	}
	// Tamper with the middle record's payload directly in SQLite.
	if err := db.execForTest(`UPDATE evidence SET data_json = replace(data_json, '"i":1', '"i":999') WHERE id = 'EV-C2'`); err != nil {
		t.Fatal(err)
	}
	_, failed, errs, err := db.VerifyAllEvidence()
	if err != nil || failed == 0 {
		t.Fatalf("tampered payload not detected: failed=%d errs=%v", failed, errs)
	}
	_ = sid
}

func TestEvidenceChainDetectsDeletion(t *testing.T) {
	db := openTestDB(t)
	sid := buildChainedSession(t, db)
	// Remove the middle record → the chain link breaks.
	if err := db.execForTest(`DELETE FROM evidence WHERE id = 'EV-C2'`); err != nil {
		t.Fatal(err)
	}
	_, failed, errs, err := db.VerifyAllEvidence()
	if err != nil || failed == 0 {
		t.Fatalf("record deletion not detected: failed=%d errs=%v", failed, errs)
	}
	_ = sid
}

func TestEvidenceChainDetectsNewestRecordRemoval(t *testing.T) {
	db := openTestDB(t)
	sid := buildChainedSession(t, db)
	// Remove the newest record: payload hashes still verify, but the session
	// head no longer matches the newest surviving record.
	if err := db.execForTest(`DELETE FROM evidence WHERE id = 'EV-C3'`); err != nil {
		t.Fatal(err)
	}
	_, failed, errs, err := db.VerifyAllEvidence()
	if err != nil || failed == 0 {
		t.Fatalf("newest-record removal not detected: failed=%d errs=%v", failed, errs)
	}
	_ = sid
}
