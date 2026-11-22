// GraphQL object-level verification battery (Master Prompt §26, §29): an
// observed operation is replayed as the owner (baseline) and as an
// unauthorized principal (observation), with negative control, public
// probe, cache analysis, repeatability and evidence. Findings route through
// the central policy with the object-level battery — GraphQL BOLA is
// object-level authorization; the transport is recorded in the title.
package verification

import (
	"context"
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/graphql"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
)

// VerifyGraphQL replays one harvested operation against an owned object.
// owner is the owning profile, attacker the non-owner; identifier is the
// object identifier the operation addresses (inline or via variables).
func (e *Engine) VerifyGraphQL(ctx context.Context, op graphql.Operation, item TestItem) *finding.Finding {
	e.stats.attempts.Add(1)
	if item.Category == "" {
		item.Category = "horizontal_object_access"
	}
	item.Body = graphql.RenderRequest(op)
	item.ContentType = "application/json"
	title := fmt.Sprintf("GraphQL %s bypass for %s '%s' via %s",
		transportLabel(op), item.Resource, item.RedactedID(), redact.URL(op.Endpoint))
	f := e.newFinding(item, title)
	e.persist(f)
	bat := &battery{evidenceOK: true}

	attacker, err := e.pickAttacker(item.Owner)
	if err != nil {
		e.finish(f, finding.StateInconclusive, 0, err.Error(), "")
		return f
	}

	sep := e.Auth.VerifySeparation(ctx, e.Client, []string{item.Owner, attacker})
	cand := Candidate{
		Category:          item.Category,
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

	gqlPost := func(profile string, op graphql.Operation, evTitle string) wireResult {
		headers, herr := e.Auth.Headers(profile)
		res := wireResult{}
		if herr != nil {
			res.reqErr = herr
			return res
		}
		headers["Content-Type"] = "application/json"
		x := e.Client.Do(ctx, "POST", op.Endpoint, httpclient.Options{
			Headers: headers, Body: []byte(graphql.RenderRequest(op)), ContentType: "application/json",
		})
		if x != nil {
			rec, cerr := e.Evid.CaptureExchange("", e.Session, x, evTitle)
			if cerr != nil {
				res.evErr = cerr
			} else {
				res.evID = rec.ID
			}
		}
		res.x = x
		return res
	}

	// Owner baseline: the operation, with the object's identifier, executed
	// as the owner must return the object data.
	ownerRes := gqlPost(item.Owner, op, "GraphQL owner baseline")
	if ownerRes.evErr != nil {
		bat.noteEvidenceLoss(ownerRes.evErr)
	}
	ownerX := ownerRes.x
	if ownerRes.reqErr != nil || !ownerX.Succeeded() {
		e.finish(f, finding.StateInconclusive, 0,
			"GraphQL owner baseline failed ("+wireErrText(ownerRes)+") — cannot establish any comparison baseline", ownerRes.evID)
		return f
	}
	if !containsIdentifier(ownerX.Body, item.Identifier) && !containsIdentifier(ownerX.RawBody, item.Identifier) {
		e.finish(f, finding.StateInconclusive, 0,
			"GraphQL owner baseline does not contain the target object identifier — operation/identifier mismatch", ownerRes.evID)
		return f
	}
	cand.OwnerBaselineOK = true
	cand.ResourceIdentityOK = true
	f.AddControl(finding.Control{Name: finding.ControlOwnerBaseline, Status: finding.StatusPass,
		Profile: item.Owner, HTTPStatus: ownerX.Status, EvidenceID: ownerRes.evID})

	// Negative control: same operation with a nonexistent identifier.
	negOp := op
	negOp.Variables = graphql.SwapID(op.Variables, item.Identifier, mutatedIdentifier(item.Identifier))
	negOp.Query = strings.ReplaceAll(op.Query, item.Identifier, mutatedIdentifier(item.Identifier))
	negRes := gqlPost(attacker, negOp, "GraphQL negative control (nonexistent object)")
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
			Profile: attacker, Detail: "negative control did not execute (" + briefErr(negX) + ")"})
	}

	// Unauthorized replay: the operation as the non-owner.
	attRes := gqlPost(attacker, op, fmt.Sprintf("GraphQL unauthorized access as %s", attacker))
	if attRes.evErr != nil {
		bat.noteEvidenceLoss(attRes.evErr)
	}
	attX := attRes.x
	if attRes.reqErr != nil || !attX.Succeeded() {
		e.finish(f, finding.StateError, 0,
			"GraphQL unauthorized request failed ("+wireErrText(attRes)+") after retries", attRes.evID)
		return f
	}
	f.Requester = attacker
	f.AddControl(finding.Control{Name: finding.ControlNonOwnerAccess, Status: finding.StatusPass,
		Profile: attacker, HTTPStatus: attX.Status, EvidenceID: attRes.evID})

	// §26 partial-data analysis: GraphQL errors WITH partial data are not
	// proof of full object access.
	if body := pickBody(attX); strings.Contains(body, "\"errors\"") && !strings.Contains(body, item.Identifier) {
		e.finish(f, finding.StateInconclusive, 0.5,
			"GraphQL response contains errors with only partial data — object access not established", attRes.evID)
		return f
	}

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
		e.finish(f, finding.StateSuspected, conf, reason, attRes.evID)
		return f
	}

	// Cache analysis: a shared cache can serve the owner's GraphQL response.
	if e.Cfg.CacheBust {
		bust := op
		bust.Endpoint = addCacheBuster(op.Endpoint)
		bustRes := gqlPost(attacker, bust, "GraphQL cache-busted unauthorized access")
		if bustRes.evErr != nil {
			bat.noteEvidenceLoss(bustRes.evErr)
		}
		if !bustRes.transportOK() {
			f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
				Profile: attacker, Detail: "cache-busted request did not execute (" + briefErr(bustRes.x) + ")"})
		} else {
			bustBody := pickBody(bustRes.x)
			cacheHeaders := attX.CacheEvidence()
			switch {
			case !containsIdentifier(bustBody, item.Identifier):
				f.AddControl(finding.Control{Name: finding.ControlCacheAnalysis, Status: finding.StatusFail,
					Detail: "cache-busted request did not reproduce the object data (headers: " + cacheHeaders + ")", EvidenceID: bustRes.evID})
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
	consistent, repeatEv, repeatEvErr := e.repeatability(ctx, item, attacker, ownerX, negX)
	if repeatEvErr != nil {
		bat.noteEvidenceLoss(repeatEvErr)
	}
	if !consistent {
		f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusFail,
			Profile: attacker, Detail: "GraphQL access did not reproduce consistently", EvidenceID: repeatEv})
		e.finish(f, finding.StateInconclusive, 0.4,
			"GraphQL cross-account access was not reproducible across repeats", repeatEv)
		return f
	}
	cand.RepeatOK = true
	f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusPass,
		Profile: attacker, EvidenceID: repeatEv})

	// Public-content probe: identical data without credentials is public.
	anonRes := gqlPost(auth.AnonymousProfile, op, "GraphQL public-content probe (no credentials)")
	if anonRes.evErr != nil {
		bat.noteEvidenceLoss(anonRes.evErr)
	}
	if anonRes.transportOK() {
		if pubBody := pickBody(anonRes.x); containsIdentifier(pubBody, item.Identifier) {
			f.AddControl(finding.Control{Name: finding.ControlPublicContent, Status: finding.StatusFail,
				Profile: auth.AnonymousProfile, EvidenceID: anonRes.evID,
				Detail: "unauthenticated request received the object data — public content"})
			e.finish(f, finding.StateRejected, 0,
				"GraphQL object data is equally available WITHOUT credentials — public exposure rather than an authorization failure", anonRes.evID)
			return f
		}
		cand.PublicProbeDone = true
		f.AddControl(finding.Control{Name: finding.ControlPublicContent, Status: finding.StatusPass,
			Profile: auth.AnonymousProfile, EvidenceID: anonRes.evID,
			Detail: "unauthenticated request does not receive the object data"})
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
	e.finish(f, finalVerdict, f.Confidence, finalReason, attRes.evID)
	return f
}

// pickBody prefers the raw body when available (GraphQL payloads carry
// dynamic values the evidence redaction may mask).
func pickBody(x *httpclient.Exchange) string {
	if x == nil {
		return ""
	}
	if x.RawBody != "" {
		return x.RawBody
	}
	return x.Body
}

func transportLabel(op graphql.Operation) string {
	if op.Kind == "mutation" {
		return "mutation authorization"
	}
	return "object access"
}

// graphqlIdentifiers returns the identifiers an operation addresses (from
// its query text and string variable values) that look like object ids.
func graphqlIdentifiers(op graphql.Operation) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || len(s) > 128 || seen[s] {
			return
		}
		if endpoints.LooksIdentifierLike(s) {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(op.Query)
	for _, v := range op.Variables {
		switch t := v.(type) {
		case string:
			add(t)
		case []any:
			for _, item := range t {
				if s, ok := item.(string); ok {
					add(s)
				}
			}
		case map[string]any:
			for _, item := range t {
				if s, ok := item.(string); ok {
					add(s)
				}
			}
		}
	}
	return out
}
