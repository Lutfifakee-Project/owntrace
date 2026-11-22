// Package verification implements the evidence-based authorization testing
// engine.
//
// Core policy (Master Prompt §4.1): a CONFIRMED verdict requires ALL of the
// mandatory prerequisites collected in Candidate and enforced by
// Candidate.Evaluate — the single central confirmation gate. No verification
// category computes a final verdict on its own; each one runs its control
// battery, fills the Candidate, and lets the policy decide. HTTP 200 alone,
// similarity alone, identifier presence alone, weakened configuration, or a
// missing control can never produce CONFIRMED.
package verification

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// EvidenceSink is the evidence persistence contract used by the engine.
// It is an interface so tests can inject failing stores and prove that
// evidence-loss blocks CONFIRMED (Master Prompt §4.4).
type EvidenceSink interface {
	Capture(findingID, sessionID, kind, title string, data any) (*evidence.Record, error)
	CaptureExchange(findingID, sessionID string, x *httpclient.Exchange, title string) (*evidence.Record, error)
}

// FindingStore persists findings.
type FindingStore interface {
	SaveFinding(f *finding.Finding) error
}

// Engine configuration.
type Engine struct {
	Client  *httpclient.Client
	Auth    *auth.Manager
	Scope   *scope.Checker
	Evid    EvidenceSink
	Store   FindingStore
	Cfg     config.Verification
	Log     *logger.Logger
	Session string

	// stats carries authorization-coverage accounting (§33). Every Verify*
	// battery increments attempts; batteries refused entirely by the safety
	// guards before their first request increment blockedChecks. The scan
	// summary derives ChecksExecuted/SafetySkipped from these counters, so a
	// request prevented before execution is never counted as executed.
	stats engineStats
}

// engineStats is the concurrency-safe coverage-accounting accumulator.
type engineStats struct {
	attempts      atomic.Int64 // verification batteries started
	blockedChecks atomic.Int64 // batteries with EVERY request safety-refused
	blockedReqs   atomic.Int64 // individual requests safety-refused (incl. partial)
}

// ChecksAttempted returns the number of verification batteries started.
func (e *Engine) ChecksAttempted() int64 { return e.stats.attempts.Load() }

// ChecksSafetyBlocked returns the number of batteries the safety guards
// refused entirely (no request of that check was ever executed).
func (e *Engine) ChecksSafetyBlocked() int64 { return e.stats.blockedChecks.Load() }

// SafetyBlockedRequests returns the number of individual requests the safety
// guards prevented before execution, including extra requests inside
// otherwise-executed checks.
func (e *Engine) SafetyBlockedRequests() int64 { return e.stats.blockedReqs.Load() }

// TestItem is one authorization test coordinate.
type TestItem struct {
	URL          string
	Method       string
	Resource     string
	Identifier   string
	Owner        string // owning profile
	OwnerState   ownership.State
	Tenant       string
	Category     finding.Category
	ExtraHeaders map[string]string
	EndpointID   string
	Note         string
	// Body/ContentType carry a request payload for repeatable non-GET
	// batteries (GraphQL over HTTP, §26): repeatability must replay the
	// exact operation, not a bare method+URL probe.
	Body        string
	ContentType string
}

// RedactedID renders the identifier safely in titles and reports.
func (t *TestItem) RedactedID() string {
	if len(t.Identifier) > 64 || strings.ContainsAny(t.Identifier, "@:") {
		return redact.Value(t.Identifier)
	}
	return t.Identifier
}

// newFinding scaffolds a finding for an item and transitions it to CANDIDATE.
func (e *Engine) newFinding(item TestItem, title string) *finding.Finding {
	f := &finding.Finding{
		// URL participates in the ID: two declared items may share identifier
		// and owner (e.g. an object and its redirect surface) and must stay
		// distinct findings.
		ID:           finding.NewID(e.Session, item.EndpointID, string(item.Category), item.Identifier+"|"+item.Owner+"|"+item.URL),
		SessionID:    e.Session,
		Category:     item.Category,
		State:        finding.StateDiscovered,
		Title:        title,
		Method:       strings.ToUpper(orDefault(item.Method, "GET")),
		URL:          redact.URL(item.URL),
		EndpointID:   item.EndpointID,
		Resource:     item.Resource,
		Identifier:   item.Identifier,
		OwnerProfile: item.Owner,
		OwnerState:   string(item.OwnerState),
		Remediation:  finding.DefaultRemediation(item.Category),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	_ = f.Transition(finding.StateCandidate, "candidate object identified from "+string(item.OwnerState)+" ownership record", "")
	_ = f.Transition(finding.StateTesting, "starting verification controls", "")
	return f
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// wireResult is the outcome of one profile-tagged request, separating
// transport success from evidence-persistence success.
type wireResult struct {
	x      *httpclient.Exchange
	evID   string
	evErr  error // evidence persistence failure (exchange may still be usable)
	reqErr error // profile/credential setup failure (x is nil)
}

func (w wireResult) transportOK() bool { return w.x != nil && w.x.Err == "" && w.x.Status > 0 }

// request performs one profile-tagged request and captures evidence.
// Evidence capture failures are returned, never swallowed.
func (e *Engine) request(ctx context.Context, profile, rawURL, method string, item TestItem, evTitle string) wireResult {
	headers, err := e.Auth.Headers(profile)
	if err != nil {
		return wireResult{reqErr: fmt.Errorf("profile %s: %w", profile, err)}
	}
	for k, v := range item.ExtraHeaders {
		if _, exists := headers[k]; !exists {
			headers[k] = v
		}
	}
	opts := httpclient.Options{Headers: headers}
	if item.Body != "" {
		opts.Body = []byte(item.Body)
		if item.ContentType != "" {
			opts.ContentType = item.ContentType
		}
	}
	x := e.Client.Do(ctx, method, rawURL, opts)
	if x != nil && x.SafetyBlocked {
		e.stats.blockedReqs.Add(1)
	}
	res := wireResult{x: x}
	if x != nil {
		rec, cerr := e.Evid.CaptureExchange("", e.Session, x, evTitle)
		if cerr != nil {
			res.evErr = fmt.Errorf("evidence capture failed: %w", cerr)
			e.Log.Errorf("evidence capture failed for %s %s: %v", method, redact.URL(rawURL), cerr)
		} else {
			res.evID = rec.ID
		}
	}
	e.Log.Debugf("verify[%s] %s %s -> %s", profile, method, redact.URL(rawURL), xStatus(x))
	return res
}

func xStatus(x *httpclient.Exchange) string {
	if x == nil {
		return "nil"
	}
	if x.Err != "" {
		return "err:" + x.Err
	}
	return strconv.Itoa(x.Status)
}

func briefErr(x *httpclient.Exchange) string {
	if x == nil || x.Err == "" {
		return ""
	}
	return x.Err
}

// wireErrText renders the failure reason of a wire result (profile setup or
// transport), nil-safe.
func wireErrText(w wireResult) string {
	if w.reqErr != nil {
		return w.reqErr.Error()
	}
	return briefErr(w.x)
}

// battery carries shared per-item state across the control battery.
type battery struct {
	evidenceOK bool // every required evidence record persisted
	detail     string
}

func (b *battery) noteEvidenceLoss(err error) {
	b.evidenceOK = false
	if err != nil && b.detail == "" {
		b.detail = err.Error()
	}
}

// VerifyItem runs the full control battery for one test item and persists a
// finding. It always produces a finding (any terminal state), routed through
// the central confirmation policy.
func (e *Engine) VerifyItem(ctx context.Context, item TestItem) *finding.Finding {
	e.stats.attempts.Add(1)
	title := fmt.Sprintf("%s access to %s '%s' owned by %s",
		categoryLabel(item.Category), item.Resource, item.RedactedID(), item.Owner)
	f := e.newFinding(item, title)
	e.persist(f)
	bat := &battery{evidenceOK: true}

	attacker, err := e.pickAttacker(item.Owner)
	if err != nil {
		e.finish(f, finding.StateInconclusive, 0, err.Error(), "")
		return f
	}

	// Control 1: identity separation. Proven-same identities and unverified
	// identities both block CONFIRMED unconditionally — configuration can
	// only decide whether the whole run aborts early, never whether a
	// same-identity finding confirms (Master Prompt §4.1 #5, §9.3).
	sep := e.Auth.VerifySeparation(ctx, e.Client, []string{item.Owner, attacker})
	cand := Candidate{
		OwnerState:        item.OwnerState,
		OwnerFloorMet:     ownerStateMeetsFloor(item.OwnerState, e.Cfg.MinOwnerStateForConfirmed),
		EvidencePersisted: true,
	}
	switch {
	case sep.Distinct && sep.Verified:
		cand.IdentityDistinct = true
		f.AddControl(finding.Control{Name: finding.ControlIdentitySeparation, Status: finding.StatusPass,
			Detail: "distinct identities verified via identity probes"})
	case !sep.Distinct:
		cand.IdentitySameIdentity = true
		cand.IdentityUnverified = true
		f.AddControl(finding.Control{Name: finding.ControlIdentitySeparation, Status: finding.StatusFail,
			Detail: sep.Detail, EvidenceID: e.captureVerification(f, sep)})
	default:
		cand.IdentityUnverified = true
		f.AddControl(finding.Control{Name: finding.ControlIdentitySeparation, Status: finding.StatusSkip,
			Detail: sep.Detail, EvidenceID: e.captureVerification(f, sep)})
	}

	// Control 2: owner baseline.
	ownerRes := e.request(ctx, item.Owner, item.URL, item.Method, item,
		fmt.Sprintf("owner baseline as %s", item.Owner))
	if ownerRes.evErr != nil {
		bat.noteEvidenceLoss(ownerRes.evErr)
	}
	ownerX := ownerRes.x
	if e.baselineSafetyBlocked(ownerRes) {
		e.finish(f, finding.StateInconclusive, 0,
			"safety guard refused every request for this check (deny-by-default destructive-path/scope policy): "+wireErrText(ownerRes), ownerRes.evID)
		return f
	}
	if ownerRes.reqErr != nil || !ownerX.Succeeded() {
		e.finish(f, finding.StateInconclusive, 0,
			"owner baseline request failed ("+wireErrText(ownerRes)+") — cannot establish any comparison baseline", ownerRes.evID)
		return f
	}
	f.AddControl(finding.Control{Name: finding.ControlOwnerBaseline, Status: finding.StatusPass,
		Profile: item.Owner, HTTPStatus: ownerX.Status, Detail: fmt.Sprintf("owner access returned HTTP %d", ownerX.Status),
		EvidenceID: ownerRes.evID})
	if ownerX.IsRedirect() && len(ownerX.Redirects) > 0 {
		e.finish(f, finding.StateInconclusive, 0,
			fmt.Sprintf("owner baseline redirected (%s) — ownership baseline unreliable", ownerX.Redirects[len(ownerX.Redirects)-1].URL), ownerRes.evID)
		return f
	}
	if d := classifyDenial(ownerX.Status, ownerX.Body); d != denialNone {
		e.finish(f, finding.StateInconclusive, 0,
			fmt.Sprintf("owner baseline denied (HTTP %d) — profile likely misconfigured or object does not exist", ownerX.Status), ownerRes.evID)
		return f
	}
	if !containsIdentifier(ownerX.Body, item.Identifier) {
		e.finish(f, finding.StateInconclusive, 0,
			"owner baseline response does not contain the target object identifier — endpoint/identifier mismatch, or the endpoint does not return object data", ownerRes.evID)
		return f
	}
	cand.OwnerBaselineOK = true
	cand.ResourceIdentityOK = true
	f.AddControl(finding.Control{Name: finding.ControlResourceIdentity, Status: finding.StatusPass,
		Detail: "owner baseline response contains the target object identifier", EvidenceID: ownerRes.evID})

	// Control 3: negative control (nonexistent object, attacker context).
	// Transport success is mandatory for a CONFIRMED path: a control that
	// cannot execute is not a passing control (§4.1 #8).
	negID := mutatedIdentifier(item.Identifier)
	negURL := replaceIdentifier(item.URL, item.Identifier, negID)
	negRes := e.request(ctx, attacker, negURL, item.Method, item,
		fmt.Sprintf("negative control as %s (nonexistent object)", attacker))
	if negRes.evErr != nil {
		bat.noteEvidenceLoss(negRes.evErr)
	}
	negX := negRes.x
	if negRes.transportOK() {
		cand.NegativeControlDone = true
		f.AddControl(finding.Control{Name: finding.ControlNegativeControl, Status: finding.StatusPass,
			Profile: attacker, HTTPStatus: negX.Status,
			Detail:     fmt.Sprintf("nonexistent object returns HTTP %d (app denial behavior reference)", negX.Status),
			EvidenceID: negRes.evID})
	} else {
		f.AddControl(finding.Control{Name: finding.ControlNegativeControl, Status: finding.StatusFail,
			Profile: attacker, Detail: "negative control did not execute (" + briefErr(negX) + "): denial behavior unknown"})
	}

	// Control 4: non-owner access test.
	attRes := e.request(ctx, attacker, item.URL, item.Method, item,
		fmt.Sprintf("cross-account access as %s", attacker))
	if attRes.evErr != nil {
		bat.noteEvidenceLoss(attRes.evErr)
	}
	attX := attRes.x
	if attRes.reqErr != nil || !attX.Succeeded() {
		e.finish(f, finding.StateError, 0,
			"non-owner request failed ("+wireErrText(attRes)+") after retries", attRes.evID)
		return f
	}
	f.Requester = attacker
	f.AddControl(finding.Control{Name: finding.ControlNonOwnerAccess, Status: finding.StatusPass,
		Profile: attacker, HTTPStatus: attX.Status,
		Detail:     fmt.Sprintf("non-owner response: HTTP %d, %d bytes", attX.Status, len(attX.Body)),
		EvidenceID: attRes.evID})

	// Decision matrix (observation, not verdict).
	verdict, reason, conf := e.classify(item, ownerX, attX, negX, attacker)
	cand.Detail = bat.detail
	switch verdict {
	case finding.StateRejected:
		e.finish(f, finding.StateRejected, 0, reason, attRes.evID)
		return f
	case finding.StateError:
		e.finish(f, finding.StateError, 0, reason, attRes.evID)
		return f
	case finding.StateConfirmed:
		cand.AccessObserved = true
	case finding.StateSuspected:
		// Access indicators without full data establishment — cannot be a
		// candidate; report SUSPECTED with the matrix reason.
		e.finish(f, finding.StateSuspected, conf, reason, attRes.evID)
		return f
	}

	// Property-level (BOPLA) re-route (§24): when the operator declared
	// restricted properties and the unauthorized response exposes one that
	// exists on the object, the finding is a property-level authorization
	// failure — a separate finding type, never folded into object-level
	// IDOR. The finding ID keeps the planned coordinates (stable across
	// runs); the classification reflects the discovered weakness.
	if props := e.exposedRestrictedProps(ownerX.Body, attX.Body); len(props) > 0 {
		f.Category = finding.CatBOPLA
		f.Remediation = finding.DefaultRemediation(finding.CatBOPLA)
		cand.Category = finding.CatBOPLA
		cand.RestrictedPropertyDeclared = true
		detail := "exposed restricted properties: " + strings.Join(props, ", ")
		if cand.Detail != "" {
			detail += "; " + cand.Detail
		}
		cand.Detail = detail
	}

	// Cache analysis (mandatory for confirmation): a shared cache can serve
	// the owner's response to the attacker. When the operator disabled
	// cache-busting the analysis cannot run and CONFIRMED is impossible —
	// the invariant holds regardless of configuration (§9.3).
	if e.Cfg.CacheBust {
		cand.CacheAnalysisDone = e.cacheAnalysis(ctx, item, attacker, ownerX, attX, negX, f, bat, &cand)
	}
	// Cache refuted the observation entirely → artifact, not access.
	if !cand.CacheAnalysisDone && attX.CacheEvidence() != "" {
		// Headers present AND bust did not reproduce → artifact suspicion;
		// handled inside cacheAnalysis via control record. Keep candidate
		// flow: policy will downgrade to SUSPECTED.
		_ = attX
	}

	// Repeatability: flaky access is INCONCLUSIVE (stronger than the policy's
	// generic SUSPECTED downgrade; the CONFIRMED emission is still gated).
	consistent, repeatEv, repeatEvErr := e.repeatability(ctx, item, attacker, ownerX, negX)
	if repeatEvErr != nil {
		bat.noteEvidenceLoss(repeatEvErr)
	}
	if !consistent {
		f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusFail,
			Profile: attacker, Detail: "access did not reproduce consistently", EvidenceID: repeatEv})
		e.finish(f, finding.StateInconclusive, 0.4,
			"cross-account access was not reproducible across "+strconv.Itoa(e.Cfg.Repeats)+" repeats (flaky or conditional behavior)", repeatEv)
		return f
	}
	cand.RepeatOK = true
	f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusPass,
		Profile: attacker, Detail: fmt.Sprintf("access reproduced %d/%d times", e.Cfg.Repeats, e.Cfg.Repeats),
		EvidenceID: repeatEv})

	// Public-content probe (mandatory): if the object data is equally
	// available WITHOUT credentials, the content is not identity-protected —
	// public exposure, not a horizontal authorization failure. A probe that
	// cannot execute leaves the question open and blocks CONFIRMED.
	anonRes := e.request(ctx, auth.AnonymousProfile, item.URL, item.Method, item,
		"public-content probe (no credentials)")
	if anonRes.evErr != nil {
		bat.noteEvidenceLoss(anonRes.evErr)
	}
	if anonRes.transportOK() {
		pubVerdict, _, _ := e.classify(item, ownerX, anonRes.x, negX, attacker)
		if pubVerdict == finding.StateConfirmed {
			f.AddControl(finding.Control{Name: finding.ControlPublicContent, Status: finding.StatusFail,
				Profile: auth.AnonymousProfile, HTTPStatus: anonRes.x.Status,
				Detail:     "unauthenticated request reproduced the same object data — content is public",
				EvidenceID: anonRes.evID})
			e.finish(f, finding.StateRejected, 0,
				"object content is equally available WITHOUT credentials — public data exposure rather than an identity-dependent authorization failure (covered by the anonymous-access finding)", anonRes.evID)
			return f
		}
		cand.PublicProbeDone = true
		f.AddControl(finding.Control{Name: finding.ControlPublicContent, Status: finding.StatusPass,
			Profile: auth.AnonymousProfile, HTTPStatus: anonRes.x.Status,
			Detail:     "unauthenticated request does not receive the object data — access is identity-dependent",
			EvidenceID: anonRes.evID})
	} else {
		f.AddControl(finding.Control{Name: finding.ControlPublicContent, Status: finding.StatusFail,
			Profile: auth.AnonymousProfile, Detail: "public-content probe did not execute (" + briefErr(anonRes.x) + ")"})
	}

	cand.EvidencePersisted = bat.evidenceOK
	f.Confidence = 0.9
	finalVerdict, finalReason := cand.Evaluate()
	if finalVerdict != finding.StateConfirmed {
		f.Confidence = 0.55
	}
	e.setReproduction(f, item, ownerX, attX)
	e.finish(f, finalVerdict, f.Confidence, finalReason, attRes.evID)
	return f
}

// cacheAnalysis runs the cache-bust control for a confirmation candidate.
// Returns whether the analysis ESTABLISHED that the observed response was not
// a shared-cache artifact. It records the control outcome on the finding.
func (e *Engine) cacheAnalysis(ctx context.Context, item TestItem, attacker string,
	ownerX, attX, negX *httpclient.Exchange, f *finding.Finding, bat *battery, cand *Candidate) bool {

	bustRes := e.request(ctx, attacker, addCacheBuster(item.URL), item.Method, item, "cache-busted non-owner access")
	if bustRes.evErr != nil {
		bat.noteEvidenceLoss(bustRes.evErr)
	}
	if !bustRes.transportOK() {
		f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
			Profile: attacker, Detail: "cache-busted request did not execute (" + briefErr(bustRes.x) + ") — cannot rule out cache artifact"})
		return false
	}
	bustVerdict, _, _ := e.classify(item, ownerX, bustRes.x, negX, attacker)
	cacheHeaders := attX.CacheEvidence()
	switch {
	case bustVerdict == finding.StateRejected || bustVerdict == finding.StateError:
		f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
			Profile: attacker, Detail: "cache-busted request did not reproduce access; cache artifact suspected (headers: " + cacheHeaders + ")",
			EvidenceID: bustRes.evID})
		return false
	case bustVerdict == finding.StateConfirmed && cacheHeaders != "":
		// The cache headers make a shared-cache artifact plausible and the
		// buster did not change the outcome — the artifact hypothesis cannot
		// be ruled out.
		f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
			Profile: attacker, Detail: "cache headers present (" + cacheHeaders + ") and cache-busted retry reproduced access — shared-cache artifact cannot be ruled out",
			EvidenceID: bustRes.evID})
		return false
	default:
		f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusPass,
			Profile: attacker, Detail: "cache-busted request reproduced access without cache headers — artifact ruled out",
			EvidenceID: bustRes.evID})
		return true
	}
}

// VerifyAnonymous runs the anonymous-access category for one item. The
// anonymous requester is structurally distinct (no credentials), so identity
// separation holds without probes; every other mandatory control — negative
// control, cache analysis, repeatability, evidence — still gates CONFIRMED.
func (e *Engine) VerifyAnonymous(ctx context.Context, item TestItem) *finding.Finding {
	e.stats.attempts.Add(1)
	anonItem := item
	anonItem.Category = finding.CatAnonymous
	anonItem.Owner = item.Owner
	title := fmt.Sprintf("anonymous (unauthenticated) access to %s '%s'", item.Resource, item.RedactedID())
	f := e.newFinding(anonItem, title)
	e.persist(f)
	bat := &battery{evidenceOK: true}

	cand := Candidate{
		OwnerState:        item.OwnerState,
		OwnerFloorMet:     ownerStateMeetsFloor(item.OwnerState, e.Cfg.MinOwnerStateForConfirmed),
		IdentityDistinct:  true, // structural: no credentials vs. credentials
		EvidencePersisted: true,
	}

	// Baseline: the owner can access the object.
	ownerRes := e.request(ctx, item.Owner, item.URL, item.Method, item, "owner baseline for anonymous test")
	if ownerRes.evErr != nil {
		bat.noteEvidenceLoss(ownerRes.evErr)
	}
	ownerX := ownerRes.x
	if e.baselineSafetyBlocked(ownerRes) {
		e.finish(f, finding.StateInconclusive, 0,
			"safety guard refused every request for this check (deny-by-default destructive-path/scope policy): "+wireErrText(ownerRes), ownerRes.evID)
		return f
	}
	if !ownerX.Succeeded() || !containsIdentifier(ownerX.Body, item.Identifier) || classifyDenial(ownerX.Status, ownerX.Body) != denialNone {
		e.finish(f, finding.StateInconclusive, 0, "owner baseline failed or did not return the object; anonymous comparison meaningless", ownerRes.evID)
		return f
	}
	cand.OwnerBaselineOK = true
	cand.ResourceIdentityOK = true
	f.AddControl(finding.Control{Name: finding.ControlOwnerBaseline, Status: finding.StatusPass,
		Profile: item.Owner, HTTPStatus: ownerX.Status, EvidenceID: ownerRes.evID})

	// Negative control: anonymous request for a nonexistent object.
	negID := mutatedIdentifier(item.Identifier)
	negURL := replaceIdentifier(item.URL, item.Identifier, negID)
	negRes := e.request(ctx, auth.AnonymousProfile, negURL, item.Method, anonItem,
		"anonymous negative control (nonexistent object)")
	if negRes.evErr != nil {
		bat.noteEvidenceLoss(negRes.evErr)
	}
	negX := negRes.x
	if negRes.transportOK() {
		cand.NegativeControlDone = true
		f.AddControl(finding.Control{Name: finding.ControlNegativeControl, Status: finding.StatusPass,
			Profile: auth.AnonymousProfile, HTTPStatus: negX.Status, EvidenceID: negRes.evID})
	} else {
		f.AddControl(finding.Control{Name: finding.ControlNegativeControl, Status: finding.StatusFail,
			Profile: auth.AnonymousProfile, Detail: "negative control did not execute (" + briefErr(negX) + ")"})
	}

	// Anonymous access test.
	anonRes := e.request(ctx, auth.AnonymousProfile, item.URL, item.Method, anonItem, "anonymous access")
	if anonRes.evErr != nil {
		bat.noteEvidenceLoss(anonRes.evErr)
	}
	anonX := anonRes.x
	if anonRes.reqErr != nil || !anonX.Succeeded() {
		e.finish(f, finding.StateError, 0, "anonymous request failed: "+wireErrText(anonRes), anonRes.evID)
		return f
	}
	f.Requester = auth.AnonymousProfile
	f.AddControl(finding.Control{Name: finding.ControlAnonymousAccess, Status: finding.StatusPass,
		Detail:     fmt.Sprintf("anonymous response: HTTP %d, %d bytes", anonX.Status, len(anonX.Body)),
		EvidenceID: anonRes.evID})

	verdict, reason, conf := e.classify(anonItem, ownerX, anonX, negX, auth.AnonymousProfile)
	switch verdict {
	case finding.StateRejected:
		e.finish(f, finding.StateRejected, 0, reason, anonRes.evID)
		return f
	case finding.StateError:
		e.finish(f, finding.StateError, 0, reason, anonRes.evID)
		return f
	case finding.StateConfirmed:
		cand.AccessObserved = true
	case finding.StateSuspected:
		e.finish(f, finding.StateSuspected, conf, reason, anonRes.evID)
		return f
	}

	// The anonymous test IS the public-content probe by definition.
	cand.PublicProbeDone = true

	// Cache analysis (mandatory, same rules as horizontal).
	if e.Cfg.CacheBust {
		bustRes := e.request(ctx, auth.AnonymousProfile, addCacheBuster(item.URL), item.Method, anonItem, "cache-busted anonymous access")
		if bustRes.evErr != nil {
			bat.noteEvidenceLoss(bustRes.evErr)
		}
		if !bustRes.transportOK() {
			f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
				Profile: auth.AnonymousProfile, Detail: "cache-busted request did not execute (" + briefErr(bustRes.x) + ")"})
		} else {
			bustVerdict, _, _ := e.classify(anonItem, ownerX, bustRes.x, negX, auth.AnonymousProfile)
			cacheHeaders := anonX.CacheEvidence()
			switch {
			case bustVerdict != finding.StateConfirmed:
				f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
					Detail: "cache-busted anonymous request did not reproduce access (headers: " + cacheHeaders + ")", EvidenceID: bustRes.evID})
			case cacheHeaders != "":
				f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
					Detail: "cache headers present (" + cacheHeaders + ") and buster ignored — artifact cannot be ruled out", EvidenceID: bustRes.evID})
			default:
				cand.CacheAnalysisDone = true
				f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusPass, EvidenceID: bustRes.evID})
			}
		}
	}

	// Repeatability.
	consistent, repeatEv, repeatEvErr := e.repeatability(ctx, anonItem, auth.AnonymousProfile, ownerX, negX)
	if repeatEvErr != nil {
		bat.noteEvidenceLoss(repeatEvErr)
	}
	if !consistent {
		f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusFail,
			Detail: "anonymous access did not reproduce consistently", EvidenceID: repeatEv})
		e.finish(f, finding.StateInconclusive, 0.4, "anonymous access not reproducible", repeatEv)
		return f
	}
	cand.RepeatOK = true
	f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusPass,
		Detail: "anonymous access reproduced", EvidenceID: repeatEv})

	cand.EvidencePersisted = bat.evidenceOK
	f.Confidence = 0.85
	finalVerdict, finalReason := cand.Evaluate()
	if finalVerdict != finding.StateConfirmed {
		f.Confidence = 0.5
	}
	e.setReproduction(f, anonItem, ownerX, anonX)
	e.finish(f, finalVerdict, f.Confidence, finalReason, anonRes.evID)
	return f
}

// VerifyVertical tests a privileged endpoint against a non-privileged
// profile. The role baseline plays the owner-baseline role; similarity with
// the privileged response is only an ACCESS OBSERVATION — the central policy
// additionally requires an executed negative control (nonexistent admin
// path), a public-content probe (a generic admin page served to everyone is
// NOT a role bypass), cache analysis, repeatability, verified distinct
// identities and persisted evidence before CONFIRMED.
func (e *Engine) VerifyVertical(ctx context.Context, rawURL, method string, ep *endpoints.Endpoint) *finding.Finding {
	admin, attacker := e.pickRoles()
	if admin == "" || attacker == "" {
		return nil // cannot test without role context
	}
	return e.verifyVerticalPair(ctx, rawURL, method, ep, admin, attacker)
}

// VerifyVerticalPair runs the vertical battery for one explicit
// (privileged, non-privileged) profile pair — the role-matrix building block.
func (e *Engine) VerifyVerticalPair(ctx context.Context, rawURL, method string, ep *endpoints.Endpoint, admin, attacker string) *finding.Finding {
	if admin == "" || attacker == "" || admin == attacker {
		return nil
	}
	return e.verifyVerticalPair(ctx, rawURL, method, ep, admin, attacker)
}

func (e *Engine) verifyVerticalPair(ctx context.Context, rawURL, method string, ep *endpoints.Endpoint, admin, attacker string) *finding.Finding {
	e.stats.attempts.Add(1)
	// Function-level authorization testing (§24 BFLA): the endpoint itself is
	// the protected function; no owned object is involved. The finding type
	// is therefore broken_function_level_authorization, distinct from
	// object-level vertical BOLA.
	item := TestItem{
		URL: rawURL, Method: method, Resource: "admin-surface", Identifier: rawURL,
		Owner: admin, OwnerState: ownership.StateDeclared, Category: finding.CatBFLA,
		ExtraHeaders: headerMap(ep), EndpointID: ep.ID,
	}
	title := fmt.Sprintf("function-level authorization bypass on privileged endpoint %s", redact.URL(rawURL))
	f := e.newFinding(item, title)
	e.persist(f)
	bat := &battery{evidenceOK: true}

	sep := e.Auth.VerifySeparation(ctx, e.Client, []string{admin, attacker})
	if !sep.Verified {
		f.AddControl(finding.Control{Name: finding.ControlIdentitySeparation, Status: finding.StatusFail, Detail: sep.Detail})
		e.finish(f, finding.StateInconclusive, 0, "identity separation between role profiles not verified: "+sep.Detail, "")
		return f
	}
	f.AddControl(finding.Control{Name: finding.ControlIdentitySeparation, Status: finding.StatusPass})

	// §29 BFLA battery: known function permissions (the endpoint is a
	// declared privileged function) and role context (both profiles carry
	// role metadata; the role baseline control below proves privileged
	// behavior). Owner-baseline/resource-identity/ownership-floor do not
	// apply — there is no owned object.
	cand := Candidate{
		Category:                finding.CatBFLA,
		IdentityDistinct:        true,
		FunctionPermissionKnown: ep.Adminish,
		RoleContextOK:           strings.TrimSpace(e.roleOf(admin)) != "" && strings.TrimSpace(e.roleOf(attacker)) != "",
		EvidencePersisted:       true,
	}

	// Role baseline (admin): proves the function's privileged behavior.
	adminRes := e.request(ctx, admin, rawURL, item.Method, item, "role baseline (admin)")
	if adminRes.evErr != nil {
		bat.noteEvidenceLoss(adminRes.evErr)
	}
	adminX := adminRes.x
	if e.baselineSafetyBlocked(adminRes) {
		e.finish(f, finding.StateInconclusive, 0,
			"safety guard refused every request for this check (deny-by-default destructive-path/scope policy): "+wireErrText(adminRes), adminRes.evID)
		return f
	}
	if !adminX.Succeeded() || classifyDenial(adminX.Status, adminX.Body) != denialNone || adminX.Status == 404 || len(strings.TrimSpace(adminX.Body)) == 0 {
		e.finish(f, finding.StateInconclusive, 0,
			fmt.Sprintf("role baseline failed (HTTP %d) — cannot establish privileged behavior", adminX.Status), adminRes.evID)
		return f
	}
	f.AddControl(finding.Control{Name: finding.ControlRoleBaseline, Status: finding.StatusPass,
		Profile: admin, HTTPStatus: adminX.Status, EvidenceID: adminRes.evID})

	// Negative control: a nonexistent admin path. If the endpoint answers
	// similar content for it, the surface does not resolve anything — decoy.
	negURL := mutateAdminPath(rawURL)
	negRes := e.request(ctx, attacker, negURL, item.Method, item, "vertical negative control (nonexistent admin path)")
	if negRes.evErr != nil {
		bat.noteEvidenceLoss(negRes.evErr)
	}
	negX := negRes.x
	if negRes.transportOK() {
		cand.NegativeControlDone = true
		f.AddControl(finding.Control{Name: finding.ControlNegativeControl, Status: finding.StatusPass,
			Profile: attacker, HTTPStatus: negX.Status, EvidenceID: negRes.evID})
	} else {
		f.AddControl(finding.Control{Name: finding.ControlNegativeControl, Status: finding.StatusFail,
			Profile: attacker, Detail: "vertical negative control did not execute (" + briefErr(negX) + ")"})
	}

	// Role bypass attempt.
	attRes := e.request(ctx, attacker, rawURL, item.Method, item, "role bypass attempt (non-admin)")
	if attRes.evErr != nil {
		bat.noteEvidenceLoss(attRes.evErr)
	}
	attX := attRes.x
	if attRes.reqErr != nil || !attX.Succeeded() {
		e.finish(f, finding.StateError, 0, "non-privileged request failed: "+wireErrText(attRes), attRes.evID)
		return f
	}
	f.Requester = attacker
	f.AddControl(finding.Control{Name: finding.ControlNonOwnerAccess, Status: finding.StatusPass,
		Profile: attacker, HTTPStatus: attX.Status,
		Detail:     fmt.Sprintf("non-admin response: HTTP %d, %d bytes", attX.Status, len(attX.Body)),
		EvidenceID: attRes.evID})

	verdict, reason, conf := e.classify(item, adminX, attX, negX, attacker)
	switch verdict {
	case finding.StateRejected:
		e.finish(f, finding.StateRejected, 0, reason, attRes.evID)
		return f
	case finding.StateError:
		e.finish(f, finding.StateError, 0, reason, attRes.evID)
		return f
	case finding.StateConfirmed:
		cand.AccessObserved = true
	case finding.StateSuspected:
		e.finish(f, finding.StateSuspected, conf, reason, attRes.evID)
		return f
	}

	// Public-content probe: a privileged page served identically to
	// unauthenticated visitors is a public page, not a role bypass.
	anonRes := e.request(ctx, auth.AnonymousProfile, rawURL, item.Method, item, "public-content probe (vertical)")
	if anonRes.evErr != nil {
		bat.noteEvidenceLoss(anonRes.evErr)
	}
	if anonRes.transportOK() {
		pubVerdict, _, _ := e.classify(item, adminX, anonRes.x, negX, attacker)
		if pubVerdict == finding.StateConfirmed {
			f.AddControl(finding.Control{Name: finding.ControlPublicContent, Status: finding.StatusFail,
				Profile: auth.AnonymousProfile, HTTPStatus: anonRes.x.Status,
				Detail:     "unauthenticated request received the same privileged-looking content — public page, not a role bypass",
				EvidenceID: anonRes.evID})
			e.finish(f, finding.StateRejected, 0,
				"the privileged-looking content is equally available WITHOUT credentials — public surface rather than an authorization failure", anonRes.evID)
			return f
		}
		cand.PublicProbeDone = true
		f.AddControl(finding.Control{Name: finding.ControlPublicContent, Status: finding.StatusPass,
			Profile: auth.AnonymousProfile, HTTPStatus: anonRes.x.Status,
			Detail:     "unauthenticated request does not receive the privileged content — access is role-dependent",
			EvidenceID: anonRes.evID})
	} else {
		f.AddControl(finding.Control{Name: finding.ControlPublicContent, Status: finding.StatusFail,
			Profile: auth.AnonymousProfile, Detail: "public-content probe did not execute (" + briefErr(anonRes.x) + ")"})
	}

	// Cache analysis (mandatory).
	if e.Cfg.CacheBust {
		bustRes := e.request(ctx, attacker, addCacheBuster(rawURL), item.Method, item, "cache-busted role bypass attempt")
		if bustRes.evErr != nil {
			bat.noteEvidenceLoss(bustRes.evErr)
		}
		if !bustRes.transportOK() {
			f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
				Profile: attacker, Detail: "cache-busted request did not execute (" + briefErr(bustRes.x) + ")"})
		} else {
			bustVerdict, _, _ := e.classify(item, adminX, bustRes.x, negX, attacker)
			cacheHeaders := attX.CacheEvidence()
			switch {
			case bustVerdict != finding.StateConfirmed:
				f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
					Detail: "cache-busted request did not reproduce the privileged content (headers: " + cacheHeaders + ")", EvidenceID: bustRes.evID})
			case cacheHeaders != "":
				f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
					Detail: "cache headers present (" + cacheHeaders + ") and buster ignored — artifact cannot be ruled out", EvidenceID: bustRes.evID})
			default:
				cand.CacheAnalysisDone = true
				f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusPass, EvidenceID: bustRes.evID})
			}
		}
	}

	// Repeatability.
	consistent, repeatEv, repeatEvErr := e.repeatability(ctx, item, attacker, adminX, negX)
	if repeatEvErr != nil {
		bat.noteEvidenceLoss(repeatEvErr)
	}
	if !consistent {
		f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusFail,
			Detail: "role bypass did not reproduce consistently", EvidenceID: repeatEv})
		e.finish(f, finding.StateInconclusive, 0.4, "role bypass not reproducible", repeatEv)
		return f
	}
	cand.RepeatOK = true
	f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusPass, EvidenceID: repeatEv})

	cand.EvidencePersisted = bat.evidenceOK
	f.Confidence = 0.9
	finalVerdict, finalReason := cand.Evaluate()
	if finalVerdict != finding.StateConfirmed {
		f.Confidence = 0.55
	}
	e.setReproduction(f, item, adminX, attX)
	e.finish(f, finalVerdict, f.Confidence, finalReason, attRes.evID)
	return f
}

// mutateAdminPath builds a nonexistent variant of an admin URL by prefixing
// the last path segment (e.g. /api/v1/admin/stats → /api/v1/admin/ot-nonexistent-stats).
func mutateAdminPath(raw string) string {
	q := ""
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		q = raw[i:]
		raw = raw[:i]
	}
	idx := strings.LastIndex(raw, "/")
	seg := raw[idx+1:]
	if seg == "" {
		return raw + "ot-nonexistent" + q
	}
	return raw[:idx+1] + "ot-nonexistent-" + seg + q
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
