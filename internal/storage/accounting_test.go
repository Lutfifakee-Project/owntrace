package storage

// Regression test (owner acceptance defect, 2026-11-22): the persisted state
// counts are the single source of truth for every displayed total. Duplicate
// finding events sharing one ID must upsert into ONE row, and
// CountFindingsByState must equal the actual finding cardinality.

import (
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/finding"
)

func mkFinding(id, state string) *finding.Finding {
	return &finding.Finding{ID: id, SessionID: "s-acc", State: finding.State(state),
		Title: "t", Method: "GET", URL: "http://api.test/x"}
}

func TestCountFindingsByStateMatchesCardinality(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "acc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sessID, err := db.BeginSession("acc", "{}")
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range []*finding.Finding{
		mkFinding("F-A", "CONFIRMED"),
		mkFinding("F-B", "CONFIRMED"),
		mkFinding("F-C", "REJECTED"),
	} {
		f.SessionID = sessID
		if err := db.SaveFinding(f); err != nil {
			t.Fatalf("save %s: %v", f.ID, err)
		}
	}
	// Duplicate EVENT: same finding ID re-reported with a different state
	// (role-matrix second attacker) must UPSERT, not add a row.
	dup := mkFinding("F-C", "CONFIRMED")
	dup.SessionID = sessID
	dup.Reason = "second attacker event"
	if err := db.SaveFinding(dup); err != nil {
		t.Fatal(err)
	}

	got, err := db.CountFindingsByState(sessID)
	if err != nil {
		t.Fatal(err)
	}
	// The duplicate event upserts: F-C is overwritten to the latest event's
	// state (state=excluded.state) but stays ONE row — the event never adds
	// cardinality. This is exactly the event-vs-row gap the scan summary must
	// never display (fixed by deriving counts from persisted rows).
	want := map[string]int{"CONFIRMED": 3}
	for st, n := range want {
		if got[st] != n {
			t.Fatalf("state %s: got %d, want %d (counts must equal persisted cardinality)", st, got[st], n)
		}
	}
	total := 0
	for _, v := range got {
		total += v
	}
	list, err := db.ListFindings(sessID, "")
	if err != nil {
		t.Fatal(err)
	}
	if total != len(list) {
		t.Fatalf("count total %d != cardinality %d", total, len(list))
	}
	if len(list) != 3 {
		t.Fatalf("duplicate event added a row: %d rows, want 3", len(list))
	}
	// The upserted row carries the LATEST event's state and reason.
	for _, f := range list {
		if f.ID == "F-C" && f.State != finding.StateConfirmed {
			t.Fatalf("F-C state = %s, want CONFIRMED (latest event wins on upsert)", f.State)
		}
		if f.ID == "F-C" && f.Reason != "second attacker event" {
			t.Fatalf("F-C reason = %q, want the second event's reason", f.Reason)
		}
	}
}
