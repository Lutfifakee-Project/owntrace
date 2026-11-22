// Package evidence captures reproducible, integrity-protected evidence for
// findings. Every record is canonical-JSON hashed (SHA-256) at creation time;
// verification recomputes the hash to prove evidence has not silently
// changed. Records are append-only: no update or delete path exists.
//
// Tamper-evidence model: records are chained per session — each record
// stores the SHA-256 of the previous record of that session, and the session
// row keeps the chain head. `owntrace results integrity` recomputes every
// hash and walks every chain, detecting payload modification, record
// deletion (broken link), forged insertion (link mismatch) and deletion of
// the newest record (head mismatch). This is tamper-EVIDENT, not
// tamper-PROOF: an attacker able to rewrite the database can rebuild a whole
// chain; defeating that requires anchoring the chain head outside the
// database (see docs/evidence-and-reporting.md).
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
)

// Kind values.
const (
	KindHTTPExchange   = "http_exchange"
	KindVerification   = "verification_step"
	KindOwnershipProof = "ownership_proof"
	KindScopeSnapshot  = "scope_snapshot"
	KindSessionEvent   = "session_event"
	KindWorkflow       = "workflow_step"
	KindGraphQL        = "graphql_probe"
)

// Record is one immutable evidence artifact. PrevSHA256 links it to the
// previous record of the same session ("" for a session's first record).
type Record struct {
	ID         string    `json:"id"`
	FindingID  string    `json:"finding_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	Kind       string    `json:"kind"`
	Title      string    `json:"title,omitempty"`
	Data       any       `json:"data"`
	SHA256     string    `json:"sha256"`
	PrevSHA256 string    `json:"prev_sha256,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// CanonicalJSON serializes v deterministically (sorted map keys, stable
// encoding) so hashes are reproducible across runs.
func CanonicalJSON(v any) ([]byte, error) {
	var buf json.RawMessage
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	buf = b
	// Re-marshal through generic decode to normalize key order.
	var generic any
	if err := json.Unmarshal(buf, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(sortJSON(generic))
}

func sortJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(t))
		for _, k := range keys {
			out[k] = sortJSON(t[k])
		}
		return out
	case []any:
		for i := range t {
			t[i] = sortJSON(t[i])
		}
		return t
	default:
		return v
	}
}

func hashOf(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// NewID derives an evidence identifier.
func NewID(n int) string {
	return fmt.Sprintf("EV-%s-%04d", time.Now().UTC().Format("20060102"), n)
}

// ExchangeData is the sanitized HTTP exchange stored as evidence.
type ExchangeData struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	Status          int               `json:"status"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	FinalURL        string            `json:"final_url,omitempty"`
	Redirects       []httpclient.Hop  `json:"redirects,omitempty"`
	ScopeBlocked    bool              `json:"scope_blocked,omitempty"`
	DurationMs      int64             `json:"duration_ms"`
}

// ExchangeFromHTTPClient converts a captured exchange into evidence form
// (already redacted by the client; URL redaction re-applied defensively).
func ExchangeFromHTTPClient(x *httpclient.Exchange) *ExchangeData {
	if x == nil {
		return nil
	}
	return &ExchangeData{
		Method:          x.Method,
		URL:             redact.URL(x.RequestURL),
		RequestHeaders:  x.RequestHeaders,
		RequestBody:     x.RequestBody,
		Status:          x.Status,
		ResponseHeaders: x.ResponseHeaders,
		Body:            x.Body,
		FinalURL:        x.FinalURL,
		Redirects:       x.Redirects,
		ScopeBlocked:    x.ScopeBlocked,
		DurationMs:      x.DurationMs,
	}
}

// Build creates a record from arbitrary data, computing its hash.
func Build(id, findingID, sessionID, kind, title string, data any) (*Record, error) {
	canonical, err := CanonicalJSON(data)
	if err != nil {
		return nil, fmt.Errorf("canonicalize evidence data: %w", err)
	}
	return &Record{
		ID:        id,
		FindingID: findingID,
		SessionID: sessionID,
		Kind:      kind,
		Title:     title,
		Data:      json.RawMessage(canonical),
		SHA256:    hashOf(canonical),
		CreatedAt: time.Now().UTC(),
	}, nil
}

// Verify recomputes the integrity hash of stored data against the recorded
// hash. Returns an error when the evidence has been tampered with.
func (r *Record) Verify() error {
	var raw json.RawMessage
	if b, ok := r.Data.(json.RawMessage); ok {
		raw = b
	} else {
		canonical, err := CanonicalJSON(r.Data)
		if err != nil {
			return err
		}
		raw = canonical
	}
	// Normalize again to be safe when Data arrived from the DB.
	var generic any
	if err := json.Unmarshal(raw, &generic); err == nil {
		if nb, err := json.Marshal(sortJSON(generic)); err == nil {
			raw = nb
		}
	}
	if hashOf(raw) != r.SHA256 {
		return fmt.Errorf("evidence %s integrity check FAILED (hash mismatch)", r.ID)
	}
	return nil
}

// Engine persists evidence through the storage backend, maintaining the
// per-session hash chain.
type Engine struct {
	store Store
	mu    sync.Mutex // serializes Capture so chain order matches append order
}

// Store is the persistence contract the evidence engine requires.
type Store interface {
	SaveEvidence(r *Record) error
	GetEvidence(findingID string) ([]*Record, error)
	NextEvidenceSeq() int
	// LastEvidenceHash returns the chain head (hash of the newest record)
	// for a session, or "" when the session has no evidence yet.
	LastEvidenceHash(sessionID string) (string, error)
}

// NewEngine builds the capture engine.
func NewEngine(store Store) *Engine {
	return &Engine{store: store}
}

// Capture stores one evidence record, chaining it to the session's current
// head. Data must be JSON-serializable and already redacted by its producer.
// Persistence failures are RETURNED, never swallowed: verdicts that require
// evidence must treat a failed capture as a missing control.
func (e *Engine) Capture(findingID, sessionID, kind, title string, data any) (*Record, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev, err := e.store.LastEvidenceHash(sessionID)
	if err != nil {
		return nil, fmt.Errorf("read evidence chain head: %w", err)
	}
	// The sequence counter lives in the STORE (persistent, monotonic): an
	// in-process counter would restart on every new Engine and collide with
	// existing evidence rows in the same database.
	id := fmt.Sprintf("EV-%s-%06d", time.Now().UTC().Format("20060102"), e.store.NextEvidenceSeq())
	rec, err := Build(id, findingID, sessionID, kind, title, data)
	if err != nil {
		return nil, err
	}
	rec.PrevSHA256 = prev
	if err := e.store.SaveEvidence(rec); err != nil {
		return nil, fmt.Errorf("save evidence %s: %w", rec.ID, err)
	}
	return rec, nil
}

// CaptureExchange stores an HTTP exchange as evidence.
func (e *Engine) CaptureExchange(findingID, sessionID string, x *httpclient.Exchange, title string) (*Record, error) {
	if x == nil {
		return nil, fmt.Errorf("nil exchange")
	}
	d := ExchangeFromHTTPClient(x)
	if title == "" {
		title = fmt.Sprintf("%s %s -> HTTP %d", x.Method, x.RequestURL, x.Status)
	}
	return e.Capture(findingID, sessionID, KindHTTPExchange, title, d)
}

// List returns all evidence for a finding.
func (e *Engine) List(findingID string) ([]*Record, error) {
	return e.store.GetEvidence(findingID)
}
