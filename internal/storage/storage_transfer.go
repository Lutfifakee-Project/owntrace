// Storage transfer (Master Prompt §35–§36): consistent database backup,
// integrity checking, and evidence-verified session export/import bundles.
// Every export re-verifies the session's evidence hashes and chain before
// writing; every import re-verifies them before inserting — a tampered or
// corrupted bundle is refused, never silently merged.
package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
)

// Backup writes a consistent snapshot of the whole database to destPath.
// The snapshot is taken with VACUUM INTO (a single implicit transaction),
// so it is valid even while WAL mode is active. The snapshot file gets
// 0600 permissions: backups contain assessment data.
func (d *DB) Backup(destPath string) error {
	if strings.TrimSpace(destPath) == "" {
		return fmt.Errorf("backup destination required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.db.Exec(`VACUUM INTO ?`, destPath); err != nil {
		return fmt.Errorf("vacuum into %s: %w", destPath, err)
	}
	return os.Chmod(destPath, 0o600)
}

// IntegrityCheck runs SQLite's integrity_check and fails on any report
// other than "ok".
func (d *DB) IntegrityCheck() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`PRAGMA integrity_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return err
		}
		if line != "ok" {
			problems = append(problems, line)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("integrity_check reported %d problem(s): %s", len(problems), strings.Join(problems, "; "))
	}
	return nil
}

// Bundle is the export envelope: one session with its findings, objects,
// endpoints, evidence and audit trail.
type Bundle struct {
	Schema     int                   `json:"schema_version"`
	ExportedAt string                `json:"exported_at"`
	Session    Session               `json:"session"`
	Config     string                `json:"config,omitempty"`
	Findings   []*finding.Finding    `json:"findings"`
	Objects    []*ObjectRow          `json:"objects"`
	Endpoints  []*endpoints.Endpoint `json:"endpoints"`
	Evidence   []*evidence.Record    `json:"evidence"`
	Audit      []string              `json:"audit,omitempty"`
	// Integrity is the SHA-256 over the deterministic JSON of the whole
	// bundle with this field empty. It detects ANY modification of the
	// exported content — including metadata (kind/title/timestamps) that
	// the per-record payload hash does not cover — before anything is
	// imported.
	Integrity string `json:"integrity,omitempty"`
}

// bundleIntegrity computes the bundle digest: SHA-256 over the
// deterministic JSON encoding of the bundle with Integrity cleared.
func bundleIntegrity(b Bundle) (string, error) {
	b.Integrity = ""
	raw, err := json.Marshal(&b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ExportBundle serializes one session after verifying its evidence chain.
// A tampered session cannot be exported: verification failures abort the
// export (fail-closed, §35 export validation).
func (d *DB) ExportBundle(sessionID string) ([]byte, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("session id required")
	}
	sessions, err := d.ListSessions()
	if err != nil {
		return nil, err
	}
	var sess *Session
	for i := range sessions {
		if sessions[i].ID == sessionID {
			sess = &sessions[i]
			break
		}
	}
	if sess == nil {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	if checked, failed, errs, verr := d.VerifyAllEvidence(); verr != nil {
		return nil, verr
	} else if failed > 0 {
		return nil, fmt.Errorf("evidence integrity failed (%d of %d records): %s", failed, checked, strings.Join(errs[:min3(len(errs), 3)], "; "))
	}

	findings, err := d.ListFindings(sessionID, "")
	if err != nil {
		return nil, err
	}
	objects, err := d.ListObjects(sessionID)
	if err != nil {
		return nil, err
	}
	endpoints, err := d.ListEndpoints(sessionID)
	if err != nil {
		return nil, err
	}
	evs, err := d.sessionEvidence(sessionID)
	if err != nil {
		return nil, err
	}
	audit, err := d.ListAudit(sessionID, 5000)
	if err != nil {
		return nil, err
	}

	var cfg string
	row := d.db.QueryRow(`SELECT config_json FROM sessions WHERE id = ?`, sessionID)
	_ = row.Scan(&cfg)

	b := Bundle{
		Schema:     SchemaVersion,
		ExportedAt: nowUTC(),
		Session:    *sess,
		Config:     cfg,
		Findings:   findings,
		Objects:    objects,
		Endpoints:  endpoints,
		Evidence:   evs,
		Audit:      audit,
	}
	digest, derr := bundleIntegrity(b)
	if derr != nil {
		return nil, derr
	}
	b.Integrity = digest
	out, err := json.MarshalIndent(&b, "", "  ")
	if err != nil {
		return nil, err
	}
	return out, nil
}

// sessionEvidence loads every evidence record of a session (raw payload).
func (d *DB) sessionEvidence(sessionID string) ([]*evidence.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query(`SELECT id, COALESCE(finding_id,''), COALESCE(session_id,''), kind,
		COALESCE(title,''), data_json, sha256, COALESCE(prev_sha256,''), created_at
		FROM evidence WHERE session_id = ? ORDER BY created_at, id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*evidence.Record
	for rows.Next() {
		var (
			r         evidence.Record
			data      string
			createdAt string
		)
		if err := rows.Scan(&r.ID, &r.FindingID, &r.SessionID, &r.Kind, &r.Title,
			&data, &r.SHA256, &r.PrevSHA256, &createdAt); err != nil {
			return nil, err
		}
		r.Data = jsonRaw(data)
		r.CreatedAt = parseTimeOr(createdAt, time.Now().UTC())
		out = append(out, &r)
	}
	return out, rows.Err()
}

// ImportBundle verifies a bundle's evidence payloads and chain, then inserts
// it as a NEW session (original identifiers are remapped so re-importing is
// safe). Returns the new session id and inserted counts.
func (d *DB) ImportBundle(b []byte) (newSessionID string, counts map[string]int, err error) {
	var bundle Bundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return "", nil, fmt.Errorf("parse bundle: %w", err)
	}
	if bundle.Session.ID == "" {
		return "", nil, fmt.Errorf("bundle has no session")
	}
	// Bundle-level integrity: ANY modification of the exported content
	// invalidates the digest; the import is refused before a single row
	// is inserted.
	want := bundle.Integrity
	if want == "" {
		return "", nil, fmt.Errorf("import refused: bundle carries no integrity digest")
	}
	got, derr := bundleIntegrity(bundle)
	if derr != nil {
		return "", nil, derr
	}
	if got != want {
		return "", nil, fmt.Errorf("import refused: bundle integrity digest mismatch (content modified or truncated)")
	}
	// Fail-closed evidence verification BEFORE any insert.
	var expectedPrev string
	linked := false
	for _, rec := range bundle.Evidence {
		if verr := rec.Verify(); verr != nil {
			return "", nil, fmt.Errorf("import refused: evidence %s fails verification: %w", rec.ID, verr)
		}
		if rec.PrevSHA256 != "" {
			linked = true
		}
		if linked && rec.PrevSHA256 != expectedPrev {
			return "", nil, fmt.Errorf("import refused: evidence chain link mismatch at %s", rec.ID)
		}
		expectedPrev = rec.SHA256
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	newSessionID = "IMP-" + time.Now().UTC().Format("20060102-150405") + "-" + randSuffix()
	suffix := strings.TrimPrefix(newSessionID, "IMP-")
	remapSession := func(old string) string {
		if old == bundle.Session.ID {
			return newSessionID
		}
		return old
	}
	remapFinding := func(old string) string {
		if old == "" {
			return ""
		}
		return "F-" + shortHash(old+"|"+newSessionID)
	}
	remapEvidence := func(old string) string {
		if old == "" {
			return ""
		}
		return "EV-IMP-" + shortHash(old+"|"+suffix)
	}

	counts = map[string]int{}
	tx, err := d.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = tx.Rollback() }()

	finished := bundle.Session.FinishedAt
	if finished == "" {
		finished = nowUTC()
	}
	if _, err := tx.Exec(`INSERT INTO sessions (id, name, status, started_at, finished_at, config_json, safety_summary, evidence_head)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		newSessionID, "imported:"+bundle.Session.Name, SessionCompleted,
		bundle.Session.StartedAt, finished, bundle.Config, "", expectedPrev); err != nil {
		return "", nil, fmt.Errorf("insert session: %w", err)
	}
	counts["sessions"] = 1

	evIDs := map[string]string{}
	for _, rec := range bundle.Evidence {
		newID := remapEvidence(rec.ID)
		evIDs[rec.ID] = newID
		data, err := json.Marshal(rec.Data)
		if err != nil {
			return "", nil, err
		}
		if _, err := tx.Exec(`INSERT INTO evidence (id, finding_id, session_id, kind, title, data_json, sha256, prev_sha256, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			newID, remapFinding(rec.FindingID), remapSession(rec.SessionID), rec.Kind, rec.Title,
			string(data), rec.SHA256, rec.PrevSHA256, rec.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return "", nil, fmt.Errorf("insert evidence %s: %w", newID, err)
		}
		counts["evidence"]++
	}

	for _, f := range bundle.Findings {
		f.SessionID = remapSession(f.SessionID)
		f.ID = remapFinding(f.ID)
		for i := range f.EvidenceIDs {
			f.EvidenceIDs[i] = remapEvidence(f.EvidenceIDs[i])
		}
		for i := range f.Controls {
			f.Controls[i].EvidenceID = remapEvidence(f.Controls[i].EvidenceID)
		}
		for i := range f.Transitions {
			f.Transitions[i].EvidenceID = remapEvidence(f.Transitions[i].EvidenceID)
		}
		if err := d.insertFindingTx(tx, f); err != nil {
			return "", nil, fmt.Errorf("insert finding %s: %w", f.ID, err)
		}
		counts["findings"]++
	}

	for _, o := range bundle.Objects {
		o.SessionID = newSessionID
		o.ID = "O-" + shortHash(o.ID+"|"+suffix)
		if err := d.insertObjectTx(tx, o); err != nil {
			return "", nil, fmt.Errorf("insert object: %w", err)
		}
		counts["objects"]++
	}

	for _, ep := range bundle.Endpoints {
		if err := d.insertEndpointTx(tx, newSessionID, ep); err != nil {
			return "", nil, fmt.Errorf("insert endpoint: %w", err)
		}
		counts["endpoints"]++
	}

	for _, line := range bundle.Audit {
		if _, err := tx.Exec(`INSERT INTO audit_events (session_id, ts, level, event, detail)
			VALUES (?, ?, 'info', 'imported', ?)`, newSessionID, nowUTC(), line); err != nil {
			return "", nil, fmt.Errorf("insert audit: %w", err)
		}
		counts["audit"]++
	}

	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	return newSessionID, counts, nil
}

func min3(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// shortHash renders a stable short identifier from arbitrary coordinates.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:])[:10])
}

// insertFindingTx is SaveFinding's statement on an explicit transaction
// (used by ImportBundle; SaveFinding keeps its own connection-level lock).
func (d *DB) insertFindingTx(tx *sql.Tx, f *finding.Finding) error {
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
	_, err := tx.Exec(`INSERT INTO findings
		(id, session_id, category, state, title, method, url, endpoint_id, resource, identifier,
		 owner_profile, requester, owner_state, confidence, reason, remediation,
		 controls_json, transitions_json, evidence_ids_json, reproduction_json,
		 severity, severity_source, cwe, owasp, triage_json, accepted_risk_json, suppression_json,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.SessionID, string(f.Category), string(f.State), f.Title, f.Method, f.URL, f.EndpointID,
		f.Resource, f.Identifier, f.OwnerProfile, f.Requester, f.OwnerState, f.Confidence, f.Reason,
		f.Remediation, controls, trans, evids, repro,
		string(f.Severity), f.SeveritySrc, f.CWE, f.OWASP, triage, accept, suppress,
		f.CreatedAt.UTC().Format(time.RFC3339Nano), f.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// insertObjectTx is SaveObject's statement on an explicit transaction.
func (d *DB) insertObjectTx(tx *sql.Tx, o *ObjectRow) error {
	_, err := tx.Exec(`INSERT OR REPLACE INTO objects
		(id, session_id, resource, identifier, endpoint_id, endpoint_path, owner_profile,
		 owner_state, confidence, tenant, provenance_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.SessionID, o.Resource, o.Identifier, o.EndpointID, o.EndpointPath,
		o.OwnerProfile, o.OwnerState, o.Confidence, o.Tenant, o.Provenance, o.CreatedAt)
	return err
}

// insertEndpointTx is SaveEndpoint's statement on an explicit transaction.
func (d *DB) insertEndpointTx(tx *sql.Tx, sessionID string, ep *endpoints.Endpoint) error {
	params, _ := marshalJSON(ep.Query)
	body, _ := marshalJSON(ep.Body)
	sources, _ := marshalJSON(ep.Sources)
	samples, _ := marshalJSON(ep.Samples)
	auth := ""
	if ep.Auth != "" {
		auth = string(ep.Auth)
	}
	_, err := tx.Exec(`INSERT OR REPLACE INTO endpoints
		(id, session_id, method, host, path, auth, adminish, collection, params_json, body_json, sources_json, samples_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ep.ID, sessionID, strings.ToUpper(ep.Method), ep.Host, ep.Path, auth,
		boolInt(ep.Adminish), boolInt(ep.Collection), params, body, sources, samples)
	return err
}
