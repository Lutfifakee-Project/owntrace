// Control-battery helpers for the verification engine: the decision matrix,
// repeatability, party selection, persistence and reproduction rendering.
package verification

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
)

// classify applies the decision matrix for one access observation. Its
// StateConfirmed result is an OBSERVATION ("the requester received the
// object's data"), never a final verdict — candidates must still pass the
// central confirmation policy.
func (e *Engine) classify(item TestItem, ownerX, attX, negX *httpclient.Exchange, attacker string) (finding.State, string, float64) {
	if attX.ScopeBlocked {
		return finding.StateError, "redirect chain left the authorized scope — test aborted", 0
	}
	// Redirect-to-login is a denial: an authentication surface was served.
	for _, hop := range attX.Redirects {
		loc := strings.ToLower(hop.Location)
		if strings.Contains(loc, "login") || strings.Contains(loc, "signin") || strings.Contains(loc, "/auth/") {
			return finding.StateRejected, "request redirected to an authentication surface: access denied", 0
		}
	}
	denial := classifyDenial(attX.Status, attX.Body)
	switch denial {
	case denialAuth:
		return finding.StateRejected,
			fmt.Sprintf("non-owner request denied with HTTP %d: object-level authorization enforced", attX.Status), 0
	case denialNotFound:
		if negX != nil && negX.Succeeded() && attX.Status == negX.Status &&
			jaccardSimilarity(negX.Body, attX.Body) >= 0.9 {
			return finding.StateRejected,
				"non-owner request returns the same generic not-found as the nonexistent-object negative control: object hidden and access denied", 0
		}
		return finding.StateSuspected,
			fmt.Sprintf("non-owner request returned HTTP %d but differs from the nonexistent-object negative control — possible existence or partial-data leak", attX.Status), 0.45
	case denialRedirectLogin:
		return finding.StateRejected, "request redirected to an authentication surface: access denied", 0
	}

	if !attX.Is2xx() {
		if attX.IsClientError() {
			return finding.StateRejected, fmt.Sprintf("non-owner request rejected (HTTP %d)", attX.Status), 0
		}
		return finding.StateError, fmt.Sprintf("non-owner request returned unexpected HTTP %d", attX.Status), 0
	}

	// Decoy gate: if the endpoint responds 2xx (with a similar body) to a
	// NONEXISTENT object identifier, it does not resolve objects at all —
	// whatever it returns is generic content, never object data. When the
	// negative control could not execute, the confirmation policy blocks
	// CONFIRMED separately (defense in depth).
	if negX != nil && negX.Succeeded() && negX.Is2xx() &&
		jaccardSimilarity(negX.Body, attX.Body) >= similarityThreshold {
		return finding.StateRejected,
			"endpoint responds with substantially the same content for a nonexistent object — it does not resolve the object; the response is generic content, not protected data", 0
	}

	// Vertical items carry the endpoint URL as their identifier — there is no
	// object identity to match, only privileged content equality.
	idRequired := item.Identifier != "" && item.Identifier != item.URL
	idIn := idRequired && containsIdentifier(attX.Body, item.Identifier)
	sim := jaccardSimilarity(ownerX.Body, attX.Body)
	overlap, fields := dataFieldOverlap(ownerX.Body, attX.Body)
	empty := len(strings.TrimSpace(attX.Body)) == 0

	// A genuine object read carries the object's data fields; a decoy or
	// generic page does not. When the owner baseline is JSON with enough
	// fields, the overlap is a hard gate for the access observation.
	hasDataProfile := fields >= 2 && idRequired
	switch {
	case empty:
		return finding.StateRejected, "non-owner response is empty; no object data exposed", 0
	case (!idRequired || idIn) && sim >= similarityThreshold && (!hasDataProfile || overlap >= overlapThreshold):
		if idRequired {
			return finding.StateConfirmed,
				fmt.Sprintf("non-owner response contains the target object's data (identifier present, similarity %.2f, owner-data field overlap %.2f of %d fields)", sim, overlap, fields), 0.9
		}
		return finding.StateConfirmed,
			fmt.Sprintf("non-privileged profile received the privileged response (similarity %.2f with role baseline)", sim), 0.9
	case (!idRequired || idIn) && sim >= similarityThreshold && hasDataProfile && overlap < overlapThreshold:
		return finding.StateRejected,
			fmt.Sprintf("non-owner response echoes the identifier but carries almost none of the object's data fields (overlap %.2f of %d) — generic content, not the object", overlap, fields), 0
	case idIn:
		return finding.StateSuspected,
			fmt.Sprintf("non-owner response references the object identifier but differs from owner baseline (similarity %.2f, data overlap %.2f) — partial or transformed data", sim, overlap), 0.6
	case sim >= similarityThreshold || (hasDataProfile && overlap >= overlapThreshold):
		return finding.StateSuspected,
			fmt.Sprintf("non-owner response closely matches the owner baseline (similarity %.2f, data overlap %.2f of %d) without a direct identifier reference — possible representation difference", sim, overlap, fields), 0.6
	default:
		return finding.StateRejected,
			fmt.Sprintf("HTTP %d response does not expose the target object (identifier absent, similarity %.2f, data overlap %.2f of %d) — legitimate 2xx content, not the object", attX.Status, sim, overlap, fields), 0
	}
}

// repeatability repeats the requester request; every attempt must re-establish
// the access observation. Returns the evidence id of the last repeat and any
// evidence persistence error.
func (e *Engine) repeatability(ctx context.Context, item TestItem, requester string, ownerX, negX *httpclient.Exchange) (bool, string, error) {
	var lastEvID string
	var lastEvErr error
	for i := 0; i < e.Cfg.Repeats; i++ {
		res := e.request(ctx, requester, item.URL, item.Method, item,
			fmt.Sprintf("repeatability #%d as %s", i+1, requester))
		lastEvID, lastEvErr = res.evID, res.evErr
		if res.x == nil || !res.x.Succeeded() {
			return false, lastEvID, lastEvErr
		}
		v, _, _ := e.classify(item, ownerX, res.x, negX, requester)
		if v != finding.StateConfirmed {
			return false, lastEvID, lastEvErr
		}
	}
	return true, lastEvID, lastEvErr
}

// pickAttacker chooses a cross-account requester: the first configured
// profile different from the owner, preferring non-admin profiles so that
// horizontal tests stay meaningful (admin mixing would conflate categories).
func (e *Engine) pickAttacker(owner string) (string, error) {
	var fallback string
	for _, name := range e.Auth.Names() {
		if name == owner {
			continue
		}
		if _, err := e.Auth.Headers(name); err != nil {
			continue
		}
		if p, err := e.Auth.Profile(name); err == nil && strings.EqualFold(p.Role, "admin") {
			if fallback == "" {
				fallback = name
			}
			continue
		}
		return name, nil
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no second authentication profile available for cross-account testing (configured: %v)", e.Auth.Names())
}

// pickRoles returns (adminProfile, nonAdminProfile) based on configured role
// labels; empty when roles are not configured.
func (e *Engine) pickRoles() (string, string) {
	var admin, user string
	for _, name := range e.Auth.Names() {
		p, err := e.Auth.Profile(name)
		if err != nil {
			continue
		}
		switch strings.ToLower(p.Role) {
		case "admin", "administrator":
			admin = name
		case "user", "", "member":
			if user == "" {
				user = name
			}
		}
	}
	return admin, user
}

func ownerStateMeetsFloor(state ownership.State, floor string) bool {
	rank := map[ownership.State]int{
		ownership.StateUnknown: 0, ownership.StateInferred: 1,
		ownership.StateDeclared: 2, ownership.StateConfirmed: 3,
	}
	return rank[state] >= rank[ownership.State(floor)]
}

func (e *Engine) finish(f *finding.Finding, state finding.State, conf float64, reason, evID string) {
	_ = f.Transition(state, reason, evID)
	f.Confidence = conf
	f.Reason = reason
	// Triage defaults (severity/CWE/OWASP) are applied at the single
	// finish choke point so every persisted finding carries complete,
	// category-correct mappings — including re-routed (BOPLA) findings.
	f.ApplyDefaults()
	e.persist(f)
}

// roleOf returns a profile's role label ("" when the profile is unknown or
// unlabeled). Role labels are the §29 role-context evidence for BFLA.
func (e *Engine) roleOf(name string) string {
	p, err := e.Auth.Profile(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(p.Role)
}

func (e *Engine) persist(f *finding.Finding) {
	if e.Store != nil {
		if err := e.Store.SaveFinding(f); err != nil {
			e.Log.Errorf("persist finding %s: %v", f.ID, err)
		}
	}
}

// baselineSafetyBlocked reports whether the check's FIRST request was refused
// by the safety guards before execution (deny-by-default scope/destructive
// policy). Such a check is accounted as safety-skipped — never executed —
// and it can never reach CONFIRMED because no control ran at all.
func (e *Engine) baselineSafetyBlocked(res wireResult) bool {
	if res.x != nil && res.x.SafetyBlocked {
		e.stats.blockedChecks.Add(1)
		return true
	}
	return false
}

// captureVerification persists a verification-step record; errors are not
// fatal here (the identity result itself is already recorded as a control),
// but the evidence loss is logged.
func (e *Engine) captureVerification(f *finding.Finding, sep *auth.SeparationResult) string {
	rec, err := e.Evid.Capture(f.ID, e.Session, evidence.KindVerification, "identity separation check", sep)
	if err != nil {
		e.Log.Errorf("evidence capture failed (identity separation): %v", err)
		return ""
	}
	return rec.ID
}

// setReproduction builds human reproduction steps with redacted credentials.
func (e *Engine) setReproduction(f *finding.Finding, item TestItem, ownerX, attX *httpclient.Exchange) {
	var steps []string
	if ownerX != nil {
		steps = append(steps, curlFor(item.Owner, item.Method, item.URL, ownerX))
	}
	if attX != nil {
		who := f.Requester
		if who == "" {
			who = "‹second profile›"
		}
		steps = append(steps, curlFor(who, item.Method, item.URL, attX))
	}
	f.Reproduction = steps
}

func curlFor(profile, method, rawURL string, x *httpclient.Exchange) string {
	var b strings.Builder
	b.WriteString("# as profile '" + profile + "'\ncurl -sS -X " + strings.ToUpper(orDefault(method, "GET")) + " '" + redact.URL(rawURL) + "'")
	if x != nil {
		for k, v := range x.RequestHeaders {
			if strings.EqualFold(k, "User-Agent") || strings.EqualFold(k, "Accept") {
				continue
			}
			b.WriteString(" -H '" + k + ": " + v + "'")
		}
	}
	return b.String()
}

func addCacheBuster(rawURL string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + "_otcb=" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func replaceIdentifier(rawURL, oldID, newID string) string {
	if oldID == "" {
		return rawURL
	}
	return strings.Replace(rawURL, oldID, newID, 1)
}

func headerMap(ep *endpoints.Endpoint) map[string]string {
	out := map[string]string{}
	if ep == nil {
		return out
	}
	for _, h := range ep.Headers {
		if h.Example != "" {
			out[h.Name] = h.Example
		}
	}
	return out
}

func categoryLabel(c finding.Category) string {
	switch c {
	case finding.CatHorizontal:
		return "Horizontal cross-account"
	case finding.CatVertical:
		return "Vertical role"
	case finding.CatAnonymous:
		return "Anonymous"
	case finding.CatCrossTenant:
		return "Cross-tenant"
	case finding.CatNested:
		return "Nested resource"
	default:
		return string(c)
	}
}
