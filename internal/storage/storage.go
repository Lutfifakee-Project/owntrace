// Package storage implements SQLite persistence: versioned schema, ordered
// migrations, transaction safety, session lifecycle, findings with transition
// history, append-only evidence and audit events. Plaintext credentials are
// never stored: profiles are persisted only as redacted config snapshots.
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
)

// SchemaVersion of the database layout.
const SchemaVersion = 3

// Session lifecycle statuses.
const (
	SessionRunning     = "running"
	SessionCompleted   = "completed"
	SessionInterrupted = "interrupted"
)

// DB wraps the SQLite handle with a write mutex (SQLite single-writer).
type DB struct {
	db   *sql.DB
	path string
	mu   sync.Mutex
	seq  int
}

// Open opens (creating if needed) the database and runs migrations.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// Single connection: avoids SQLITE_BUSY on concurrent writes entirely.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	d := &DB{db: db, path: path}
	if err := d.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// The database holds assessment data and evidence: enforce owner-only
	// file permissions regardless of the process umask (36).
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("chmod database: %w", err)
	}
	return d, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// migrations are applied in order; each entry must leave the schema valid.
var migrations = []string{
	// v1: base schema
	`
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	status TEXT NOT NULL,
	started_at TEXT NOT NULL,
	finished_at TEXT,
	config_json TEXT NOT NULL DEFAULT '{}',
	safety_summary TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS endpoints (
	id TEXT NOT NULL,
	session_id TEXT NOT NULL REFERENCES sessions(id),
	method TEXT NOT NULL,
	host TEXT NOT NULL,
	path TEXT NOT NULL,
	auth TEXT,
	adminish INTEGER NOT NULL DEFAULT 0,
	collection INTEGER NOT NULL DEFAULT 0,
	params_json TEXT NOT NULL DEFAULT '[]',
	body_json TEXT,
	sources_json TEXT NOT NULL DEFAULT '[]',
	samples_json TEXT NOT NULL DEFAULT '[]',
	PRIMARY KEY (session_id, id)
);
CREATE TABLE IF NOT EXISTS objects (
	id TEXT PRIMARY KEY,
	session_id TEXT NOT NULL REFERENCES sessions(id),
	resource TEXT NOT NULL,
	identifier TEXT NOT NULL,
	endpoint_id TEXT,
	endpoint_path TEXT,
	owner_profile TEXT,
	owner_state TEXT NOT NULL,
	confidence REAL NOT NULL DEFAULT 0,
	tenant TEXT,
	provenance_json TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_objects_session ON objects(session_id);
CREATE INDEX IF NOT EXISTS idx_objects_owner ON objects(owner_profile);
CREATE TABLE IF NOT EXISTS findings (
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
);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE TABLE IF NOT EXISTS evidence (
	id TEXT PRIMARY KEY,
	finding_id TEXT,
	session_id TEXT,
	kind TEXT NOT NULL,
	title TEXT,
	data_json TEXT NOT NULL,
	sha256 TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT,
	ts TEXT NOT NULL,
	level TEXT NOT NULL,
	event TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
);
`,
	// v2: tamper-evident evidence chaining — per-record previous-hash link and
	// a per-session chain head.
	`
ALTER TABLE evidence ADD COLUMN prev_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN evidence_head TEXT NOT NULL DEFAULT '';
`,
	// v3: finding triage enrichment — severity (with source), CWE/OWASP
	// mappings, operator triage notes, accepted-risk and suppression records.
	`
ALTER TABLE findings ADD COLUMN severity TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN severity_source TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN cwe TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN owasp TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN triage_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE findings ADD COLUMN accepted_risk_json TEXT;
ALTER TABLE findings ADD COLUMN suppression_json TEXT;
`,
}

func (d *DB) migrate() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}
	var current int
	row := d.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for v := current; v < len(migrations); v++ {
		tx, err := d.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d failed: %w", v+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			v+1, nowUTC()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", v+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", v+1, err)
		}
	}
	return nil
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// --- sessions ---------------------------------------------------------------

// BeginSession opens a new scan session.
func (d *DB) BeginSession(name, configJSON string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := "S-" + time.Now().UTC().Format("20060102-150405") + "-" + randSuffix()
	_, err := d.db.Exec(`INSERT INTO sessions (id, name, status, started_at, config_json) VALUES (?, ?, ?, ?, ?)`,
		id, name, SessionRunning, nowUTC(), configJSON)
	if err != nil {
		return "", fmt.Errorf("begin session: %w", err)
	}
	return id, nil
}

// FinishSession closes a session with a final status.
func (d *DB) FinishSession(id, status string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec(`UPDATE sessions SET status = ?, finished_at = ? WHERE id = ?`, status, nowUTC(), id)
	return err
}

// RecoverInterrupted marks stale running sessions as interrupted (called at
// startup after an unclean shutdown).
func (d *DB) RecoverInterrupted() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec(`UPDATE sessions SET status = ?, finished_at = ? WHERE status = ?`,
		SessionInterrupted, nowUTC(), SessionRunning)
	return err
}

// Session is a stored scan run summary.
type Session struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
}

// ListSessions returns sessions, newest first.
func (d *DB) ListSessions() ([]Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`SELECT id, name, status, started_at, COALESCE(finished_at,'') FROM sessions ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.Name, &s.Status, &s.StartedAt, &s.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// LatestSessionID returns the most recent session (any status).
func (d *DB) LatestSessionID() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var id string
	err := d.db.QueryRow(`SELECT id FROM sessions ORDER BY started_at DESC LIMIT 1`).Scan(&id)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no sessions in database")
	}
	return id, err
}

// --- endpoints --------------------------------------------------------------

// SaveEndpoint stores a discovered endpoint for the session.
func (d *DB) SaveEndpoint(sessionID string, ep *endpoints.Endpoint) error {
	params, _ := marshalJSON(ep.Query)
	body, _ := marshalJSON(ep.Body)
	sources, _ := marshalJSON(ep.Sources)
	samples, _ := marshalJSON(ep.Samples)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec(`INSERT OR REPLACE INTO endpoints
		(id, session_id, method, host, path, auth, adminish, collection, params_json, body_json, sources_json, samples_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ep.ID, sessionID, ep.Method, ep.Host, ep.Path, string(ep.Auth), boolInt(ep.Adminish), boolInt(ep.Collection),
		params, body, sources, samples)
	return err
}

// ListEndpoints returns endpoints for a session.
func (d *DB) ListEndpoints(sessionID string) ([]*endpoints.Endpoint, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`SELECT id, method, host, path, auth, adminish, collection, params_json, body_json, sources_json, samples_json
		FROM endpoints WHERE session_id = ? ORDER BY method, path`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*endpoints.Endpoint
	for rows.Next() {
		var (
			ep                     endpoints.Endpoint
			auth                   string
			adminish, coll         int
			params, body, src, smp []byte
		)
		if err := rows.Scan(&ep.ID, &ep.Method, &ep.Host, &ep.Path, &auth, &adminish, &coll,
			&params, &body, &src, &smp); err != nil {
			return nil, err
		}
		ep.Auth = endpoints.AuthRequirement(auth)
		ep.Adminish = adminish == 1
		ep.Collection = coll == 1
		_ = unmarshalJSON(params, &ep.Query)
		if len(body) > 0 && string(body) != "null" {
			var bs endpoints.BodySpec
			if unmarshalJSON(body, &bs) == nil {
				ep.Body = &bs
			}
		}
		_ = unmarshalJSON(src, &ep.Sources)
		_ = unmarshalJSON(smp, &ep.Samples)
		out = append(out, &ep)
	}
	return out, rows.Err()
}

// --- findings ---------------------------------------------------------------

// SaveFinding inserts or updates a finding (full row).
func (d *DB) SaveFinding(f *finding.Finding) error {
	controls, _ := marshalJSON(f.Controls)
	trans, _ := marshalJSON(f.Transitions)
	evids, _ := marshalJSON(f.EvidenceIDs)
	repro, _ := marshalJSON(f.Reproduction)
	triage, _ := marshalJSON(f.TriageNotes)
	var accept, suppress any
	if f.AcceptedRisk != nil {
		b, err := marshalJSON(f.AcceptedRisk)
		if err != nil {
			return err
		}
		accept = string(b)
	}
	if f.Suppression != nil {
		b, err := marshalJSON(f.Suppression)
		if err != nil {
			return err
		}
		suppress = string(b)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec(`INSERT INTO findings
		(id, session_id, category, state, title, method, url, endpoint_id, resource, identifier,
		 owner_profile, requester, owner_state, confidence, reason, remediation,
		 controls_json, transitions_json, evidence_ids_json, reproduction_json,
		 severity, severity_source, cwe, owasp, triage_json, accepted_risk_json, suppression_json,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			state=excluded.state, title=excluded.title, confidence=excluded.confidence,
			reason=excluded.reason, remediation=excluded.remediation,
			controls_json=excluded.controls_json, transitions_json=excluded.transitions_json,
			evidence_ids_json=excluded.evidence_ids_json, reproduction_json=excluded.reproduction_json,
			severity=excluded.severity, severity_source=excluded.severity_source,
			cwe=excluded.cwe, owasp=excluded.owasp, triage_json=excluded.triage_json,
			accepted_risk_json=excluded.accepted_risk_json, suppression_json=excluded.suppression_json,
			updated_at=excluded.updated_at`,
		f.ID, f.SessionID, string(f.Category), string(f.State), f.Title, f.Method, f.URL, f.EndpointID,
		f.Resource, f.Identifier, f.OwnerProfile, f.Requester, f.OwnerState, f.Confidence, f.Reason,
		f.Remediation, controls, trans, evids, repro,
		string(f.Severity), f.SeveritySrc, f.CWE, f.OWASP, triage, accept, suppress,
		f.CreatedAt.UTC().Format(time.RFC3339Nano), f.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// CountFindingsByState returns the persisted finding cardinality per state
// for a session. This is the SINGLE SOURCE OF TRUTH for state counts: the
// scan summary, report.json, results list and session persistence must all
// agree with these numbers — event-level duplicates (multiple role-matrix
// attackers producing one upserted row) must never inflate displayed counts.
func (d *DB) CountFindingsByState(sessionID string) (map[string]int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`SELECT state, COUNT(*) FROM findings WHERE session_id = ? GROUP BY state`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// ListFindings returns findings for a session, optionally filtered by state.
func (d *DB) ListFindings(sessionID string, state string) ([]*finding.Finding, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	q := `SELECT id, session_id, category, state, title, method, url, endpoint_id, resource, identifier,
		COALESCE(owner_profile,''), COALESCE(requester,''), COALESCE(owner_state,''), confidence, reason,
		COALESCE(remediation,''), controls_json, transitions_json, evidence_ids_json, reproduction_json,
		COALESCE(severity,''), COALESCE(severity_source,''), COALESCE(cwe,''), COALESCE(owasp,''),
		COALESCE(triage_json,'[]'), accepted_risk_json, suppression_json,
		created_at, updated_at FROM findings WHERE session_id = ?`
	args := []any{sessionID}
	if state != "" {
		q += ` AND state = ?`
		args = append(args, state)
	}
	q += ` ORDER BY created_at, id`
	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*finding.Finding
	for rows.Next() {
		var (
			f                                 finding.Finding
			controls, trans, evids, repro     []byte
			triage, acceptedRisk, suppression []byte
			createdAt, updatedAt              string
		)
		if err := rows.Scan(&f.ID, &f.SessionID, &f.Category, &f.State, &f.Title, &f.Method, &f.URL,
			&f.EndpointID, &f.Resource, &f.Identifier, &f.OwnerProfile, &f.Requester, &f.OwnerState,
			&f.Confidence, &f.Reason, &f.Remediation, &controls, &trans, &evids, &repro,
			&f.Severity, &f.SeveritySrc, &f.CWE, &f.OWASP, &triage, &acceptedRisk, &suppression,
			&createdAt, &updatedAt); err != nil {
			return nil, err
		}
		f.CreatedAt = parseTimeOr(createdAt, time.Now().UTC())
		f.UpdatedAt = parseTimeOr(updatedAt, time.Now().UTC())
		_ = unmarshalJSON(controls, &f.Controls)
		_ = unmarshalJSON(trans, &f.Transitions)
		_ = unmarshalJSON(evids, &f.EvidenceIDs)
		_ = unmarshalJSON(repro, &f.Reproduction)
		_ = unmarshalJSON(triage, &f.TriageNotes)
		if len(acceptedRisk) > 0 {
			var ar finding.AcceptedRisk
			if err := unmarshalJSON(acceptedRisk, &ar); err == nil {
				f.AcceptedRisk = &ar
			}
		}
		if len(suppression) > 0 {
			var sup finding.Suppression
			if err := unmarshalJSON(suppression, &sup); err == nil {
				f.Suppression = &sup
			}
		}
		out = append(out, &f)
	}
	return out, rows.Err()
}

// FindingCounts summarizes session findings by state.
func (d *DB) FindingCounts(sessionID string) (map[string]int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`SELECT state, COUNT(*) FROM findings WHERE session_id = ? GROUP BY state`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

// --- evidence ---------------------------------------------------------------

// SaveEvidence stores an evidence record (append-only) and advances the
// session's chain head when the record belongs to a session.
func (d *DB) SaveEvidence(r *evidence.Record) error {
	data, err := evidence.CanonicalJSON(r.Data)
	if err != nil {
		return fmt.Errorf("canonicalize evidence: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO evidence (id, finding_id, session_id, kind, title, data_json, sha256, prev_sha256, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.FindingID, r.SessionID, r.Kind, r.Title, string(data), r.SHA256, r.PrevSHA256,
		r.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if r.SessionID != "" {
		if _, err := tx.Exec(`UPDATE sessions SET evidence_head = ? WHERE id = ?`, r.SHA256, r.SessionID); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("advance evidence chain head: %w", err)
		}
	}
	return tx.Commit()
}

// LastEvidenceHash returns the session's evidence chain head ("" when the
// session is unknown or has no evidence yet).
// EvidenceCheckpoint returns the trusted head checkpoint of a session's
// evidence chain: the head hash and the record count. Operators anchor this
// checkpoint in external trusted storage (§35); later verification against
// the anchored head detects a full-chain rewrite by an attacker who can
// recompute every per-record hash.
func (d *DB) EvidenceCheckpoint(sessionID string) (string, int, error) {
	head, err := d.LastEvidenceHash(sessionID)
	if err != nil {
		return "", 0, err
	}
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM evidence WHERE session_id = ?`, sessionID).Scan(&n); err != nil {
		return "", 0, err
	}
	return head, n, nil
}

// VerifyAgainstHead re-verifies every stored evidence record and then checks
// that the session's current chain head still equals anchoredHead. A full
// rewrite that recomputes per-record hashes passes record verification but
// changes the head — the anchored checkpoint catches it.
func (d *DB) VerifyAgainstHead(sessionID, anchoredHead string) (checked, failed int, err error) {
	checked, failed, _, err = d.VerifyAllEvidence()
	if err != nil {
		return checked, failed, err
	}
	if failed > 0 {
		return checked, failed, fmt.Errorf("%d evidence record(s) failed integrity", failed)
	}
	head, herr := d.LastEvidenceHash(sessionID)
	if herr != nil {
		return checked, failed, herr
	}
	if head != anchoredHead {
		return checked, failed, fmt.Errorf("anchored head mismatch: records were rewritten since the checkpoint was anchored (current %q != anchored %q)", head, anchoredHead)
	}
	return checked, failed, nil
}

func (d *DB) LastEvidenceHash(sessionID string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var head string
	err := d.db.QueryRow(`SELECT evidence_head FROM sessions WHERE id = ?`, sessionID).Scan(&head)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return head, nil
}

// GetEvidence loads evidence records for a finding.
func (d *DB) GetEvidence(findingID string) ([]*evidence.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`SELECT id, finding_id, session_id, kind, COALESCE(title,''), data_json, sha256, COALESCE(prev_sha256,''), created_at
		FROM evidence WHERE finding_id = ? ORDER BY created_at, id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*evidence.Record
	for rows.Next() {
		var (
			r       evidence.Record
			data    string
			created string
		)
		if err := rows.Scan(&r.ID, &r.FindingID, &r.SessionID, &r.Kind, &r.Title, &data, &r.SHA256, &r.PrevSHA256, &created); err != nil {
			return nil, err
		}
		r.Data = jsonRaw(data)
		r.CreatedAt = parseTimeOr(created, time.Now().UTC())
		out = append(out, &r)
	}
	return out, rows.Err()
}

// NextEvidenceSeq returns the current evidence count for ID generation.
func (d *DB) NextEvidenceSeq() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seq == 0 {
		// Recover the persisted counter from the most recently inserted
		// evidence row (rowid order): an in-memory counter that restarts at
		// 1 would collide with existing rows in the same database.
		var lastID string
		row := d.db.QueryRow(`SELECT id FROM evidence ORDER BY rowid DESC LIMIT 1`)
		if err := row.Scan(&lastID); err == nil {
			if i := strings.LastIndexByte(lastID, '-'); i >= 0 {
				if v, perr := strconv.Atoi(lastID[i+1:]); perr == nil && v > d.seq {
					d.seq = v
				}
			}
		}
	}
	d.seq++
	return d.seq
}

// VerifyAllEvidence re-hashes every stored evidence record and walks every
// session's hash chain, detecting payload modification, broken links
// (deletion), forged insertions, and chain-head mismatch (newest-record
// deletion). Legacy sessions recorded before hash chaining existed are
// payload-verified and reported as legacy rather than failed.
func (d *DB) VerifyAllEvidence() (checked, failed int, errs []string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	heads := map[string]string{}
	hrows, err := d.db.Query(`SELECT id, COALESCE(evidence_head,'') FROM sessions`)
	if err != nil {
		return 0, 0, nil, err
	}
	for hrows.Next() {
		var id, head string
		if err := hrows.Scan(&id, &head); err != nil {
			hrows.Close()
			return 0, 0, nil, err
		}
		heads[id] = head
	}
	hrows.Close()
	if err := hrows.Err(); err != nil {
		return 0, 0, nil, err
	}

	rows, err := d.db.Query(`SELECT id, COALESCE(session_id,''), data_json, sha256, COALESCE(prev_sha256,'')
		FROM evidence ORDER BY session_id, created_at, id`)
	if err != nil {
		return 0, 0, nil, err
	}
	defer rows.Close()

	type chainState struct {
		expectedPrev string
		lastSHA      string
		linked       bool // at least one record carries a non-empty prev
	}
	chains := map[string]*chainState{}
	for rows.Next() {
		var (
			id, sessionID, data, want, prev string
		)
		if err := rows.Scan(&id, &sessionID, &data, &want, &prev); err != nil {
			return checked, failed, errs, err
		}
		rec := &evidence.Record{ID: id, SessionID: sessionID, Data: jsonRaw(data), SHA256: want, PrevSHA256: prev}
		checked++
		st := chains[sessionID]
		if st == nil {
			st = &chainState{}
			chains[sessionID] = st
		}
		if verr := rec.Verify(); verr != nil {
			failed++
			errs = append(errs, verr.Error())
			continue
		}
		if prev != "" {
			st.linked = true
		}
		if st.linked {
			if prev != st.expectedPrev {
				failed++
				errs = append(errs, fmt.Sprintf("evidence %s: chain link mismatch (expected prev %s…, got %s…)",
					id, short8(st.expectedPrev), short8(prev)))
			}
		}
		st.expectedPrev = rec.SHA256
		st.lastSHA = rec.SHA256
	}
	if err := rows.Err(); err != nil {
		return checked, failed, errs, err
	}
	// Head check per linked session: newest record must match the stored head.
	for sid, st := range chains {
		if !st.linked {
			continue
		}
		head := heads[sid]
		if head != "" && head != st.lastSHA {
			failed++
			errs = append(errs, fmt.Sprintf("session %s: evidence chain head mismatch (head %s…, newest record %s…) — newest record may have been removed", sid, short8(head), short8(st.lastSHA)))
		}
	}
	return checked, failed, errs, rows.Err()
}

func short8(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	if h == "" {
		return "∅"
	}
	return h
}

// --- objects ----------------------------------------------------------------

// ObjectRow is the stored ownership record.
type ObjectRow struct {
	ID           string  `json:"id"`
	SessionID    string  `json:"session_id"`
	Resource     string  `json:"resource"`
	Identifier   string  `json:"identifier"`
	EndpointID   string  `json:"endpoint_id,omitempty"`
	EndpointPath string  `json:"endpoint_path,omitempty"`
	OwnerProfile string  `json:"owner_profile"`
	OwnerState   string  `json:"owner_state"`
	Confidence   float64 `json:"confidence"`
	Tenant       string  `json:"tenant,omitempty"`
	Provenance   string  `json:"-"`
	CreatedAt    string  `json:"created_at"`
}

// SaveObject stores an ownership record.
func (d *DB) SaveObject(o *ObjectRow) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec(`INSERT OR REPLACE INTO objects
		(id, session_id, resource, identifier, endpoint_id, endpoint_path, owner_profile, owner_state, confidence, tenant, provenance_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.SessionID, o.Resource, o.Identifier, o.EndpointID, o.EndpointPath,
		o.OwnerProfile, o.OwnerState, o.Confidence, o.Tenant, o.Provenance, o.CreatedAt)
	return err
}

// ListObjects returns ownership records for a session.
func (d *DB) ListObjects(sessionID string) ([]*ObjectRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`SELECT id, session_id, resource, identifier, COALESCE(endpoint_id,''),
		COALESCE(endpoint_path,''), COALESCE(owner_profile,''), owner_state, confidence, COALESCE(tenant,''), provenance_json, created_at
		FROM objects WHERE session_id = ? ORDER BY resource, identifier`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ObjectRow
	for rows.Next() {
		var o ObjectRow
		if err := rows.Scan(&o.ID, &o.SessionID, &o.Resource, &o.Identifier, &o.EndpointID, &o.EndpointPath,
			&o.OwnerProfile, &o.OwnerState, &o.Confidence, &o.Tenant, &o.Provenance, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &o)
	}
	return out, rows.Err()
}

// --- audit ------------------------------------------------------------------

// Audit appends an audit event.
func (d *DB) Audit(sessionID, level, event, detail string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec(`INSERT INTO audit_events (session_id, ts, level, event, detail) VALUES (?, ?, ?, ?, ?)`,
		sessionID, nowUTC(), level, event, detail)
	return err
}

// ListAudit returns audit events for a session.
func (d *DB) ListAudit(sessionID string, limit int) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`SELECT ts, level, event, detail FROM audit_events WHERE session_id = ? ORDER BY id DESC LIMIT ?`,
		sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ts, level, event, detail string
		if err := rows.Scan(&ts, &level, &event, &detail); err != nil {
			return nil, err
		}
		out = append(out, strings.Join([]string{ts, level, event, detail}, "\t"))
	}
	return out, rows.Err()
}

// --- retention ---------------------------------------------------------------

// Cleanup deletes sessions older than the retention window and their rows.
func (d *DB) Cleanup(retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339Nano)
	d.mu.Lock()
	defer d.mu.Unlock()
	var ids []string
	rows, err := d.db.Query(`SELECT id FROM sessions WHERE started_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		for _, table := range []string{"endpoints", "objects", "findings", "evidence", "audit_events"} {
			if _, err := tx.Exec(`DELETE FROM `+table+` WHERE session_id = ?`, id); err != nil {
				_ = tx.Rollback()
				return 0, fmt.Errorf("cleanup %s: %w", table, err)
			}
		}
		if _, err := tx.Exec(`DELETE FROM sessions WHERE id = ?`, id); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}

// --- helpers ----------------------------------------------------------------

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func marshalJSON(v any) (string, error) {
	b, err := jsonMarshal(v)
	return string(b), err
}

func unmarshalJSON(data []byte, v any) error { return jsonUnmarshal(data, v) }

func jsonRaw(s string) json_RawMessage { return json_RawMessage(s) }

func parseTimeOr(s string, fallback time.Time) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fallback
	}
	return t
}
