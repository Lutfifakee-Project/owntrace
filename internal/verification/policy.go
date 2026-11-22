// Central confirmation policy (Master Prompt §4.1, §4.3).
//
// Every verification category must route its final verdict through
// Evaluate. The policy makes it structurally impossible to emit
// StateConfirmed without satisfying every mandatory prerequisite, and it is
// exhaustively unit-tested: each missing prerequisite is proven to block
// CONFIRMED.
package verification

import (
	"fmt"

	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
)

// Candidate collects the outcome of every verification control for one test
// item. Verification categories fill it from their control battery and then
// call Evaluate — no category may compute a final verdict on its own.
type Candidate struct {
	// Category selects the verification battery. Unknown/empty categories
	// fall through to the full object-level battery (fail-closed default).
	Category finding.Category

	// Observed access: the decision matrix established that the requester
	// received the target object's protected data (StateConfirmed-shaped
	// observation). Without this, CONFIRMED is impossible.
	//
	// Category-specific meanings:
	//   - object categories: object-specific protected data was returned to
	//     the non-owner requester.
	//   - BOPLA: a DECLARED restricted property was present in the
	//     unauthorized response.
	//   - BFLA: the privileged function executed successfully for an
	//     unauthorized role.
	//   - business flow: the flow's side effect was validated (state change
	//     observed through a verification point).
	AccessObserved bool

	// Identity: the requester is demonstrably a distinct unauthorized
	// principal. For authenticated categories this requires probe-verified
	// distinctness. For anonymous verification this is structurally true
	// (no credentials vs. credentials).
	IdentityDistinct bool
	// IdentityUnverified reports that distinctness could NOT be established
	// (missing probes, failed probes). Proven-same and unverified both
	// block CONFIRMED; they differ in the explanatory reason.
	IdentityUnverified bool
	// IdentitySameIdentity reports the stronger failure: the profiles
	// resolved to the same principal.
	IdentitySameIdentity bool

	// Owner baseline executed successfully and returned the target object.
	OwnerBaselineOK bool
	// Resource identity verified (identifier present in baseline and in the
	// attacker response when the category requires object identity).
	ResourceIdentityOK bool

	// Negative control executed successfully (transport-level) and its
	// criteria were evaluated. A control that cannot execute is not a
	// passing control.
	NegativeControlDone bool

	// Public-content probe executed and established that the data is not
	// served to unauthenticated requesters. For the anonymous category the
	// probe IS the test and is reported via AccessObserved instead.
	PublicProbeDone bool

	// Cache analysis executed and ruled out shared-cache artifacts. When
	// disabled by configuration it cannot pass: the invariant holds
	// regardless of configuration.
	CacheAnalysisDone bool

	// Repeatability satisfied.
	RepeatOK bool

	// Ownership state and whether it may support confirmation at all.
	OwnerState ownership.State
	// OwnerFloorMet reports the ownership state meets the OPERATOR's
	// configured floor (declared|confirmed). The hard invariant
	// (inferred/unknown never confirm) is checked separately and is not
	// configurable.
	OwnerFloorMet bool

	// Required evidence records were successfully persisted and integrity
	// verified. A lost evidence record blocks CONFIRMED.
	EvidencePersisted bool

	// --- BFLA (function-level) battery prerequisites --------------------------
	// §29: "For BFLA, require known function permissions and role context."
	// FunctionPermissionKnown: the endpoint is a declared privileged function
	// (admin-path pattern, role-matrix classification or operator policy) —
	// an unclassified endpoint can never prove a function-level bypass.
	FunctionPermissionKnown bool
	// RoleContextOK: the requester's role is established from profile role
	// metadata and the role baseline control ran (privileged baseline vs
	// attacker attempt).
	RoleContextOK bool

	// --- BOPLA (property-level) battery prerequisite ---------------------------
	// §29: "For BOPLA, require known restricted properties or valid policy
	// evidence and proof of unauthorized exposure or modification."
	// RestrictedPropertyDeclared: the exposed property is on the operator's
	// restricted-property list (policy evidence). Without a declaration the
	// exposure is not provably unauthorized, so it can never confirm.
	RestrictedPropertyDeclared bool

	// --- Business-flow battery prerequisites -----------------------------------
	// §29: "For business workflows, require workflow state, authorized
	// principal, expected policy, and validated side effects."
	FlowStateKnown  bool // the workflow engine executed the flow; flow state is established
	FlowPolicyKnown bool // the flow's expected access policy is operator-declared

	// Detail is a human-readable note included in downgrade reasons.
	Detail string
}

// blocked returns the reason the candidate cannot confirm, or "" when all
// mandatory prerequisites hold. The battery is selected by category; empty
// or unknown categories fall through to the full object-level battery
// (fail-closed default).
func (c Candidate) blockedReason() string {
	switch c.Category {
	case finding.CatBFLA:
		return c.blockedFunctionLevel()
	case finding.CatBOPLA:
		return c.blockedPropertyLevel()
	case finding.CatBusinessFlow:
		return c.blockedBusinessFlow()
	default:
		return c.blockedObjectLevel()
	}
}

// blockedObjectLevel is the full object-ownership battery (horizontal,
// vertical object-level, anonymous, cross-tenant, nested).
func (c Candidate) blockedObjectLevel() string {
	switch {
	case !c.AccessObserved:
		return "decision matrix did not establish access to the object's protected data"
	case c.IdentitySameIdentity:
		return "requester and owner resolve to the SAME identity — cross-account conclusion is invalid"
	case c.IdentityUnverified:
		return "requester distinctness could not be verified (identity probes missing or failed)"
	case !c.OwnerBaselineOK:
		return "owner baseline did not succeed with the target object"
	case !c.ResourceIdentityOK:
		return "object identity not verified in both baseline and non-owner responses"
	case !c.NegativeControlDone:
		return "negative control did not execute successfully — denial behavior of the application is unknown"
	case !c.PublicProbeDone:
		return "public-content probe did not execute — cannot establish that the data is not public"
	case !c.CacheAnalysisDone:
		return "cache analysis did not run or could not rule out a shared-cache artifact"
	case !c.RepeatOK:
		return "repeatability control failed"
	case !ownership.AllowedForConfirmed(c.OwnerState):
		return fmt.Sprintf("ownership state %q may never support confirmation", c.OwnerState)
	case !c.OwnerFloorMet:
		return "ownership does not meet the configured confirmation floor"
	case !c.EvidencePersisted:
		return "required evidence was not persisted — an unsupported verdict would lack its proof"
	default:
		return ""
	}
}

// blockedFunctionLevel is the BFLA battery (§24, §29). Function-level
// findings have NO owned object: owner-baseline, resource-identity and
// ownership-floor prerequisites do not apply. In their place the battery
// demands the two §29 conditions — known function permissions and role
// context — plus the generic false-positive controls (§28) and evidence.
func (c Candidate) blockedFunctionLevel() string {
	switch {
	case !c.AccessObserved:
		return "decision matrix did not establish execution of the privileged function"
	case c.IdentitySameIdentity:
		return "requester and privileged baseline resolve to the SAME identity — function-level conclusion is invalid"
	case c.IdentityUnverified:
		return "requester distinctness could not be verified (identity probes missing or failed)"
	case !c.FunctionPermissionKnown:
		return "the endpoint is not a declared privileged function — function permissions unknown (§29)"
	case !c.RoleContextOK:
		return "requester role context not established (role metadata or role baseline control missing)"
	case !c.NegativeControlDone:
		return "negative control did not execute successfully — denial behavior of the application is unknown"
	case !c.PublicProbeDone:
		return "public-content probe did not execute — cannot establish that the function is not public"
	case !c.CacheAnalysisDone:
		return "cache analysis did not run or could not rule out a shared-cache artifact"
	case !c.RepeatOK:
		return "repeatability control failed"
	case !c.EvidencePersisted:
		return "required evidence was not persisted — an unsupported verdict would lack its proof"
	default:
		return ""
	}
}

// blockedPropertyLevel is the BOPLA battery (§24, §29). Property-level
// findings are object-bound, so the full object battery applies PLUS the
// §29 condition that the exposed property is a known restricted property.
func (c Candidate) blockedPropertyLevel() string {
	if reason := c.blockedObjectLevel(); reason != "" {
		return reason
	}
	switch {
	case !c.RestrictedPropertyDeclared:
		return "the exposed property is not on the operator's restricted-property list — exposure is not provably unauthorized (§29)"
	default:
		return ""
	}
}

// blockedBusinessFlow is the sensitive-business-flow battery (§24, §29).
// Flows are state-changing sequences, not owned objects: owner-baseline,
// resource-identity and ownership-floor prerequisites do not apply; cache
// analysis (GET shared-cache artifact) and the public-content probe (GET of
// public resources) are replaced by flow-state and policy evidence, which
// are the §29 mandatory conditions. Identity separation stays mandatory.
func (c Candidate) blockedBusinessFlow() string {
	switch {
	case !c.AccessObserved:
		return "decision matrix did not establish the flow's side effect (verification point not satisfied)"
	case c.IdentitySameIdentity:
		return "requester and flow owner resolve to the SAME identity — business-flow conclusion is invalid"
	case c.IdentityUnverified:
		return "requester distinctness could not be verified (identity probes missing or failed)"
	case !c.FlowStateKnown:
		return "workflow state not established — the flow did not execute with valid preconditions (§29)"
	case !c.FlowPolicyKnown:
		return "expected access policy for the flow is not operator-declared (§29)"
	case !c.NegativeControlDone:
		return "negative control did not execute successfully — denial behavior of the flow is unknown"
	case !c.RepeatOK:
		return "repeatability control failed"
	case !c.EvidencePersisted:
		return "required evidence was not persisted — an unsupported verdict would lack its proof"
	default:
		return ""
	}
}

// Evaluate returns the final verdict for the candidate. CONFIRMED only when
// every mandatory prerequisite holds. When access was observed but a
// prerequisite is unmet, the verdict is SUSPECTED (inconclusive controls)
// with the blocking reason; when access itself was denied or refuted, the
// caller supplies that stronger verdict directly and does not reach here.
func (c Candidate) Evaluate() (finding.State, string) {
	if reason := c.blockedReason(); reason != "" {
		if c.AccessObserved {
			detail := reason
			if c.Detail != "" {
				detail += ": " + c.Detail
			}
			return finding.StateSuspected, detail
		}
		return finding.StateRejected, reason
	}
	return finding.StateConfirmed, "all mandatory verification prerequisites satisfied" + detailSuffix(c.Detail)
}

func detailSuffix(d string) string {
	if d == "" {
		return ""
	}
	return " (" + d + ")"
}

// EvaluateDenied is the explicit path for observed denials and refutations
// (401/403, generic 404, decoys, public content, redirects to login). It
// exists so categories never hand-craft REJECTED verdicts inconsistently.
func EvaluateDenied(reason string) (finding.State, string) {
	return finding.StateRejected, reason
}
