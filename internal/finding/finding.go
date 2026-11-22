// Package finding defines the vulnerability finding model and its explicit
// state machine. Every state transition carries a reason and evidence so the
// audit trail explains WHY a finding is confirmed, suspected or rejected.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
)

// State enumerates the finding lifecycle.
type State string

const (
	StateDiscovered   State = "DISCOVERED"
	StateCandidate    State = "CANDIDATE"
	StateTesting      State = "TESTING"
	StateConfirmed    State = "CONFIRMED"
	StateSuspected    State = "SUSPECTED"
	StateInconclusive State = "INCONCLUSIVE"
	StateRejected     State = "REJECTED"
	StateError        State = "ERROR"
)

// Terminal states.
func (s State) Terminal() bool {
	switch s {
	case StateConfirmed, StateSuspected, StateInconclusive, StateRejected, StateError:
		return true
	}
	return false
}

// Category classifies the authorization weakness under test.
type Category string

const (
	CatHorizontal   Category = "horizontal_object_access"
	CatVertical     Category = "vertical_role_bypass"
	CatAnonymous    Category = "anonymous_access"
	CatCrossTenant  Category = "cross_tenant_access"
	CatNested       Category = "nested_resource_authorization"
	CatBFLA         Category = "broken_function_level_authorization"
	CatBOPLA        Category = "broken_object_property_level_authorization"
	CatBusinessFlow Category = "sensitive_business_flow_bypass"
)

// Categories returns every finding category, including the adjacent
// authorization categories (BFLA/BOPLA/business-flow) that are separate
// finding types and never folded into object-level IDOR categories.
func Categories() []Category {
	return []Category{
		CatHorizontal, CatVertical, CatAnonymous, CatCrossTenant, CatNested,
		CatBFLA, CatBOPLA, CatBusinessFlow,
	}
}

// Control names used by the verification engine.
const (
	ControlIdentitySeparation = "identity_separation"
	ControlOwnerBaseline      = "owner_baseline"
	ControlNonOwnerAccess     = "non_owner_access"
	ControlAnonymousAccess    = "anonymous_access"
	ControlNegativeControl    = "negative_control"
	ControlResourceIdentity   = "resource_identity"
	ControlRepeatability      = "repeatability"
	ControlCacheAnalysis      = "cache_analysis"
	ControlRoleBaseline       = "role_baseline"
	ControlScopeValidation    = "scope_validation"
	ControlPublicContent      = "public_content_probe"
)

// ControlStatus values.
const (
	StatusPass = "PASS"
	StatusFail = "FAIL"
	StatusSkip = "SKIP"
)

// Severity is a qualitative triage rating. It is deliberately NOT a CVSS
// score: CVSS requires inputs (attack complexity metrics, scope, C/I/A) the
// engine does not measure, and fabricating them would misrepresent evidence.
// DefaultSeverity provides conservative per-category guidance; operators may
// override it through triage (SetSeverity), which records the source so
// reports can distinguish engine defaults from human judgment.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// TriageNote is one operator annotation on a finding.
type TriageNote struct {
	Author string    `json:"author"`
	At     time.Time `json:"at"`
	Text   string    `json:"text"`
}

// AcceptedRisk records an operator decision to accept a finding as a known
// risk. The finding keeps its verdict; reports flag it as accepted.
type AcceptedRisk struct {
	Reason string    `json:"reason"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

// Suppression records an operator decision to exclude a finding from report
// counts and CI exit codes. Suppression requires a justification and is kept
// in the stored record for audit; it never deletes the finding.
type Suppression struct {
	Reason string    `json:"reason"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

// Control records the outcome of one verification control.
type Control struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Profile    string `json:"profile,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Detail     string `json:"detail,omitempty"`
	EvidenceID string `json:"evidence_id,omitempty"`
}

// Transition is one movement of the state machine.
type Transition struct {
	From       State     `json:"from"`
	To         State     `json:"to"`
	Reason     string    `json:"reason"`
	At         time.Time `json:"at"`
	EvidenceID string    `json:"evidence_id,omitempty"`
}

// Finding is the core vulnerability record.
type Finding struct {
	ID           string        `json:"id"`
	SessionID    string        `json:"session_id,omitempty"`
	Category     Category      `json:"category"`
	State        State         `json:"state"`
	Title        string        `json:"title"`
	Method       string        `json:"method"`
	URL          string        `json:"url"` // redacted URL
	EndpointID   string        `json:"endpoint_id,omitempty"`
	Resource     string        `json:"resource,omitempty"`
	Identifier   string        `json:"identifier"` // raw, redact on export
	OwnerProfile string        `json:"owner_profile,omitempty"`
	Requester    string        `json:"requester_profile,omitempty"`
	OwnerState   string        `json:"owner_state,omitempty"` // ownership.State
	Confidence   float64       `json:"confidence"`
	Severity     Severity      `json:"severity,omitempty"`
	SeveritySrc  string        `json:"severity_source,omitempty"` // default|operator
	CWE          string        `json:"cwe,omitempty"`             // e.g. CWE-639
	OWASP        string        `json:"owasp,omitempty"`           // e.g. API1:2023
	TriageNotes  []TriageNote  `json:"triage_notes,omitempty"`
	AcceptedRisk *AcceptedRisk `json:"accepted_risk,omitempty"`
	Suppression  *Suppression  `json:"suppression,omitempty"`
	Reason       string        `json:"reason"` // human explanation of the verdict
	Remediation  string        `json:"remediation,omitempty"`
	Controls     []Control     `json:"controls,omitempty"`
	Transitions  []Transition  `json:"transitions,omitempty"`
	EvidenceIDs  []string      `json:"evidence_ids,omitempty"`
	Reproduction []string      `json:"reproduction,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

// NewID derives a stable finding ID from its coordinates.
func NewID(sessionID, endpointID, category, identifier string) string {
	h := sha256.Sum256([]byte(sessionID + "|" + endpointID + "|" + category + "|" + identifier))
	return "F-" + strings.ToUpper(hex.EncodeToString(h[:])[:8])
}

// Transition moves the finding to a new state, appending reason and evidence.
// Transitions out of terminal states are refused unless allowReopen is set
// (used by the verify command when re-testing an existing finding).
func (f *Finding) Transition(to State, reason, evidenceID string) error {
	from := f.State
	if from.Terminal() && to != from {
		return fmt.Errorf("finding %s is in terminal state %s; cannot transition to %s", f.ID, from, to)
	}
	if from == to {
		return nil
	}
	f.Transitions = append(f.Transitions, Transition{
		From: from, To: to, Reason: reason, At: time.Now().UTC(), EvidenceID: evidenceID,
	})
	f.State = to
	f.UpdatedAt = time.Now().UTC()
	return nil
}

// AddControl appends a control outcome and ties its evidence.
func (f *Finding) AddControl(c Control) {
	f.Controls = append(f.Controls, c)
	if c.EvidenceID != "" {
		f.EvidenceIDs = append(f.EvidenceIDs, c.EvidenceID)
	}
}

// ControlStatus returns the status of a named control ("" if absent).
func (f *Finding) ControlStatus(name string) string {
	for _, c := range f.Controls {
		if c.Name == name {
			return c.Status
		}
	}
	return ""
}

// DefaultSeverity returns the conservative default triage rating for a
// category. These are guidance defaults derived from the access class
// (unauthenticated/cross-tenant/object/property/function/flow), not measured
// impact metrics; operators override them via SetSeverity.
func DefaultSeverity(cat Category) Severity {
	switch cat {
	case CatBOPLA:
		// Property exposure: impact depends entirely on which property leaked.
		return SevMedium
	case CatHorizontal, CatVertical, CatAnonymous, CatCrossTenant,
		CatNested, CatBFLA, CatBusinessFlow:
		return SevHigh
	default:
		return SevMedium
	}
}

// DefaultCWE returns the primary CWE mapping for a category.
func DefaultCWE(cat Category) string {
	switch cat {
	case CatBOPLA:
		return "CWE-200" // exposure of sensitive information to an unauthorized actor
	case CatBFLA:
		return "CWE-862" // missing authorization on a privileged function
	case CatAnonymous:
		return "CWE-306" // missing authentication for critical function
	case CatBusinessFlow:
		return "CWE-840" // business logic errors: sensitive flow abused
	default:
		return "CWE-639" // authorization bypass through user-controlled key
	}
}

// DefaultOWASP returns the primary OWASP API Security Top 10 (2023) mapping.
func DefaultOWASP(cat Category) string {
	switch cat {
	case CatBOPLA:
		return "API3:2023" // Broken Object Property Level Authorization
	case CatBFLA:
		return "API5:2023" // Broken Function Level Authorization
	case CatBusinessFlow:
		return "API6:2023" // Unrestricted Access to Sensitive Business Flows
	default:
		return "API1:2023" // Broken Object Level Authorization (BOLA/IDOR)
	}
}

// ApplyDefaults fills severity (with source "default"), CWE and OWASP
// mappings when they are empty. It never overwrites operator-set values.
func (f *Finding) ApplyDefaults() {
	if f.Severity == "" {
		f.Severity = DefaultSeverity(f.Category)
		f.SeveritySrc = "default"
	}
	if f.CWE == "" {
		f.CWE = DefaultCWE(f.Category)
	}
	if f.OWASP == "" {
		f.OWASP = DefaultOWASP(f.Category)
	}
}

// SetSeverity records an operator severity decision (source "operator").
func (f *Finding) SetSeverity(s Severity) error {
	switch s {
	case SevInfo, SevLow, SevMedium, SevHigh, SevCritical:
	default:
		return fmt.Errorf("unknown severity %q (valid: info|low|medium|high|critical)", s)
	}
	f.Severity = s
	f.SeveritySrc = "operator"
	f.UpdatedAt = time.Now().UTC()
	return nil
}

// AddTriageNote appends an operator annotation.
func (f *Finding) AddTriageNote(author, text string) {
	f.TriageNotes = append(f.TriageNotes, TriageNote{Author: author, At: time.Now().UTC(), Text: text})
	f.UpdatedAt = time.Now().UTC()
}

// AcceptRisk marks a confirmed or suspected finding as an accepted risk with
// a mandatory justification. Risk acceptance on unverified states
// (INCONCLUSIVE/REJECTED/ERROR) is refused: there is no verified risk to
// accept.
func (f *Finding) AcceptRisk(reason, by string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("accepted-risk requires a justification")
	}
	switch f.State {
	case StateConfirmed, StateSuspected:
		f.AcceptedRisk = &AcceptedRisk{Reason: reason, By: by, At: time.Now().UTC()}
		f.UpdatedAt = time.Now().UTC()
		return nil
	default:
		return fmt.Errorf("finding %s is %s: risk can only be accepted on CONFIRMED or SUSPECTED findings", f.ID, f.State)
	}
}

// Suppress excludes a terminal finding from report counts and CI exit codes.
// Suppression requires a justification, is only valid on terminal states
// (the testing verdict must exist first), and keeps the finding stored for
// audit — it is a reporting filter, not a deletion.
func (f *Finding) Suppress(reason, by string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("suppression requires a justification")
	}
	if !f.State.Terminal() {
		return fmt.Errorf("finding %s is %s: only terminal findings can be suppressed", f.ID, f.State)
	}
	f.Suppression = &Suppression{Reason: reason, By: by, At: time.Now().UTC()}
	f.UpdatedAt = time.Now().UTC()
	return nil
}

// IsSuppressed reports whether the finding is excluded from report counts.
func (f *Finding) IsSuppressed() bool { return f.Suppression != nil }

// RedactedIdentifier renders the identifier safely for reports. Long opaque
// identifiers are masked with a stable prefix.
func (f *Finding) RedactedIdentifier() string {
	if len(f.Identifier) > 64 || strings.ContainsAny(f.Identifier, "@:") {
		h := sha256.Sum256([]byte(f.Identifier))
		return "obj_" + hex.EncodeToString(h[:])[:12]
	}
	return f.Identifier
}

// DefaultRemediation returns remediation text per category.
func DefaultRemediation(cat Category) string {
	switch cat {
	case CatHorizontal:
		return "Enforce object-level authorization on every request that addresses a resource by identifier: resolve the object, verify the authenticated principal owns (or is explicitly granted) the object, and return an authorization error otherwise. Prefer centralized authorization middleware over scattered per-handler checks."
	case CatVertical:
		return "Enforce role/permission checks server-side for privileged endpoints, in addition to hiding UI elements. Apply deny-by-default middleware for privileged route groups and verify the principal's role on every request."
	case CatAnonymous:
		return "Require authentication for the endpoint (or confirm the exposure is intentional) and reject unauthenticated requests with 401 before object resolution."
	case CatCrossTenant:
		return "Scope all object queries by the authenticated principal's tenant identifier taken from a trusted session attribute — never from client-supplied path or query parameters alone — and validate that the addressed object belongs to that tenant."
	case CatNested:
		return "When addressing nested resources (/parent/{pid}/children/{cid}), authorize the parent object AND verify the child belongs to that parent before returning child data."
	case CatBFLA:
		return "Enforce function-level authorization server-side: map every privileged endpoint and action to the roles allowed to invoke it, check the principal's role from a trusted session attribute on every request, and return an authorization error for unauthorized roles. Never rely on hidden UI or client-side routing."
	case CatBOPLA:
		return "Enforce property-level authorization: return only the properties the authenticated principal is permitted to see, validate server-side which fields a principal may read or write, and never bind request payloads wholesale to persistence layers (mass assignment)."
	case CatBusinessFlow:
		return "Protect sensitive business flows with context-aware controls: verify role, state and step-sequence server-side, rate-limit or lock automated abuse of approval/transfer/ownership operations, and never infer authorization from reachability alone."
	default:
		return "Enforce object-level authorization consistently and validate ownership server-side on every access."
	}
}

// SourceRefSummary renders provenance for reports.
func SourceRefSummary(srcs []endpoints.SourceRef) string {
	if len(srcs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(srcs))
	seen := map[string]bool{}
	for _, s := range srcs {
		key := string(s.Kind) + ":" + s.Location
		if seen[key] {
			continue
		}
		seen[key] = true
		if s.Location != "" {
			parts = append(parts, fmt.Sprintf("%s(%s)", s.Kind, s.Location))
		} else {
			parts = append(parts, string(s.Kind))
		}
	}
	return strings.Join(parts, ", ")
}
