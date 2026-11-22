package evidence_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
)

// memStore is an in-memory evidence.Store with chain-head tracking.
type memStore struct {
	mu      sync.Mutex
	records map[string]*evidence.Record
	heads   map[string]string
	seq     int
	fail    bool
}

func newMemStore() *memStore {
	return &memStore{records: map[string]*evidence.Record{}, heads: map[string]string{}}
}

func (m *memStore) SaveEvidence(r *evidence.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errorsNew("simulated storage outage")
	}
	m.records[r.ID] = r
	if r.SessionID != "" {
		m.heads[r.SessionID] = r.SHA256
	}
	return nil
}

func (m *memStore) GetEvidence(findingID string) ([]*evidence.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*evidence.Record
	for _, r := range m.records {
		if r.FindingID == findingID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) NextEvidenceSeq() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	return m.seq
}

func (m *memStore) LastEvidenceHash(sessionID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.heads[sessionID], nil
}

func errorsNew(s string) error { return &simpleError{s} }

type simpleError struct{ msg string }

func (e *simpleError) Error() string { return e.msg }

func TestCanonicalJSONDeterministic(t *testing.T) {
	a := map[string]any{"z": 1, "a": map[string]any{"q": []int{3, 1, 2}, "b": "x"}}
	b := map[string]any{"a": map[string]any{"b": "x", "q": []int{3, 1, 2}}, "z": 1}
	ca, err := evidence.CanonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := evidence.CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("canonical forms differ:\n%s\n%s", ca, cb)
	}
}

func TestBuildAndVerifyDetectsTampering(t *testing.T) {
	rec, err := evidence.Build("EV-1", "F-1", "S-1", evidence.KindHTTPExchange, "probe",
		map[string]any{"status": 200, "url": "https://api.test/x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("pristine record failed verification: %v", err)
	}
	// Modify the payload → hash mismatch.
	rec2, _ := evidence.Build(rec.ID, rec.FindingID, rec.SessionID, rec.Kind, rec.Title,
		map[string]any{"status": 500, "url": "https://api.test/x"})
	rec.Data = rec2.Data
	if err := rec.Verify(); err == nil {
		t.Fatal("tampered payload passed verification")
	}
	if !strings.Contains(rec.Verify().Error(), "hash mismatch") {
		t.Fatalf("unexpected error text: %v", rec.Verify())
	}
}

func TestEngineChainsRecordsPerSession(t *testing.T) {
	store := newMemStore()
	eng := evidence.NewEngine(store)
	var hashes []string
	for i := 0; i < 4; i++ {
		rec, err := eng.Capture("F-1", "S-chain", evidence.KindHTTPExchange, "step", map[string]any{"i": i})
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, rec.SHA256)
	}
	// Verify chain linkage: rec[i].PrevSHA256 == rec[i-1].SHA256.
	// (Single critical section: no store methods may be called while holding
	// the mutex — it is not reentrant.)
	store.mu.Lock()
	ordered := make([]*evidence.Record, 0, 4)
	bySHA := map[string]*evidence.Record{}
	for _, r := range store.records {
		bySHA[r.SHA256] = r
	}
	store.mu.Unlock()
	for _, h := range hashes {
		if r := bySHA[h]; r != nil {
			ordered = append(ordered, r)
		}
	}
	if len(ordered) != 4 {
		t.Fatalf("expected 4 records, got %d", len(ordered))
	}
	for i, r := range ordered {
		if i == 0 {
			if r.PrevSHA256 != "" {
				t.Fatalf("first record must have empty prev, got %s", r.PrevSHA256)
			}
			continue
		}
		if r.PrevSHA256 != ordered[i-1].SHA256 {
			t.Fatalf("chain broken at %d: prev=%s want=%s", i, r.PrevSHA256[:8], ordered[i-1].SHA256[:8])
		}
	}
	// Session head equals the last record's hash.
	head, _ := store.LastEvidenceHash("S-chain")
	if head != ordered[3].SHA256 {
		t.Fatalf("chain head mismatch: %s vs %s", head[:8], ordered[3].SHA256[:8])
	}
}

func TestEngineCaptureErrorPropagates(t *testing.T) {
	store := newMemStore()
	store.fail = true
	eng := evidence.NewEngine(store)
	_, err := eng.Capture("F-1", "S-1", evidence.KindHTTPExchange, "x", map[string]any{"a": 1})
	if err == nil {
		t.Fatal("persistence failure silently swallowed — evidence-required verdicts depend on this error")
	}
	if !strings.Contains(err.Error(), "simulated storage outage") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEngineConcurrentCaptureKeepsChain(t *testing.T) {
	store := newMemStore()
	eng := evidence.NewEngine(store)
	var wg sync.WaitGroup
	const n = 32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := eng.Capture("F-1", "S-conc", evidence.KindHTTPExchange, "step", map[string]any{"i": i})
			if err != nil {
				t.Errorf("capture %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	store.mu.Lock()
	if len(store.records) != n {
		t.Fatalf("lost records: %d/%d", len(store.records), n)
	}
	byHash := map[string]*evidence.Record{}
	for _, r := range store.records {
		byHash[r.SHA256] = r
	}
	store.mu.Unlock()
	// Reconstruct the chain by following prev links from the head.
	head, _ := store.LastEvidenceHash("S-conc")
	count := 0
	cur := head
	for cur != "" {
		r, ok := byHash[cur]
		if !ok {
			t.Fatalf("chain broken: hash %s missing", cur[:8])
		}
		count++
		cur = r.PrevSHA256
	}
	if count != n {
		t.Fatalf("chain walk reached %d of %d records", count, n)
	}
}
