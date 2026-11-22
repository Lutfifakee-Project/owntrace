package verification

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
)

// fullBFLA returns a candidate with every function-level battery prerequisite
// satisfied. Note: NO ownership fields — BFLA findings are function-scoped
// and must confirm without any ownership floor (§24, §29).
func fullBFLA() Candidate {
	return Candidate{
		Category:                finding.CatBFLA,
		AccessObserved:          true,
		IdentityDistinct:        true,
		FunctionPermissionKnown: true,
		RoleContextOK:           true,
		NegativeControlDone:     true,
		PublicProbeDone:         true,
		CacheAnalysisDone:       true,
		RepeatOK:                true,
		EvidencePersisted:       true,
	}
}

// TestPolicyBFLAEveryMissingPrerequisiteBlocksConfirmation proves the §29
// function-level battery: known function permissions and role context are
// mandatory, and every missing control blocks CONFIRMED.
func TestPolicyBFLAEveryMissingPrerequisiteBlocksConfirmation(t *testing.T) {
	tests := []struct {
		name         string
		mutator      func(*Candidate)
		wantFragment string
	}{
		{"access not observed", func(c *Candidate) { c.AccessObserved = false }, "privileged function"},
		{"same identity", func(c *Candidate) {
			c.IdentityDistinct = false
			c.IdentitySameIdentity = true
		}, "SAME identity"},
		{"identity unverified", func(c *Candidate) {
			c.IdentityDistinct = false
			c.IdentityUnverified = true
		}, "distinctness could not be verified"},
		{"function permissions unknown", func(c *Candidate) { c.FunctionPermissionKnown = false }, "declared privileged function"},
		{"role context missing", func(c *Candidate) { c.RoleContextOK = false }, "role context"},
		{"negative control did not execute", func(c *Candidate) { c.NegativeControlDone = false }, "negative control"},
		{"public probe did not execute", func(c *Candidate) { c.PublicProbeDone = false }, "public-content probe"},
		{"cache analysis did not run", func(c *Candidate) { c.CacheAnalysisDone = false }, "cache analysis"},
		{"repeatability failed", func(c *Candidate) { c.RepeatOK = false }, "repeatability"},
		{"evidence not persisted", func(c *Candidate) { c.EvidencePersisted = false }, "evidence"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := fullBFLA()
			tc.mutator(&c)
			state, reason := c.Evaluate()
			// Unmet control with observed access = SUSPECTED; no observed
			// access at all = REJECTED (both block CONFIRMED).
			wantState := finding.StateSuspected
			if !c.AccessObserved {
				wantState = finding.StateRejected
			}
			if state != wantState {
				t.Fatalf("state = %s, want %s; reason: %s", state, wantState, reason)
			}
			if !strings.Contains(reason, tc.wantFragment) {
				t.Fatalf("reason %q does not mention %q", reason, tc.wantFragment)
			}
		})
	}

	// The complete BFLA candidate confirms WITHOUT any ownership evidence —
	// the function battery must not demand an owned object.
	c := fullBFLA()
	state, reason := c.Evaluate()
	if state != finding.StateConfirmed {
		t.Fatalf("complete BFLA candidate blocked: %s", reason)
	}
}

// TestPolicyBFLAInferredOwnershipIrrelevant proves the ownership floor does
// NOT gate function-level findings (there is no owned object) — but also
// that the BFLA battery never accidentally confirms an OBJECT-level claim:
// the category routes the battery, nothing else.
func TestPolicyBFLAInferredOwnershipIrrelevant(t *testing.T) {
	c := fullBFLA()
	c.OwnerState = ownership.StateInferred
	c.OwnerFloorMet = false
	if state, _ := c.Evaluate(); state != finding.StateConfirmed {
		t.Fatal("ownership floor leaked into the function-level battery")
	}
}

// TestPolicyBOPLARequiresDeclaredRestrictedProperty proves §29 for BOPLA:
// the exposed property must be a known restricted property, on top of the
// full object battery (property findings are object-bound).
func TestPolicyBOPLARequiresDeclaredRestrictedProperty(t *testing.T) {
	c := fullCandidate()
	c.Category = finding.CatBOPLA
	state, reason := c.Evaluate()
	if state != finding.StateSuspected || !strings.Contains(reason, "restricted-property") {
		t.Fatalf("undeclared property exposure must not confirm: state=%s reason=%s", state, reason)
	}

	c.RestrictedPropertyDeclared = true
	if state, reason := c.Evaluate(); state != finding.StateConfirmed {
		t.Fatalf("declared property exposure must confirm: %s", reason)
	}

	// An object-level failure still blocks BOPLA (fail-closed object battery).
	c2 := fullCandidate()
	c2.Category = finding.CatBOPLA
	c2.RestrictedPropertyDeclared = true
	c2.OwnerBaselineOK = false
	if state, reason := c2.Evaluate(); state != finding.StateSuspected || !strings.Contains(reason, "owner baseline") {
		t.Fatalf("object battery must still apply to BOPLA: state=%s reason=%s", state, reason)
	}
}

// fullFlow returns a candidate with every business-flow battery prerequisite
// satisfied (§29: workflow state, authorized principal, expected policy,
// validated side effects).
func fullFlow() Candidate {
	return Candidate{
		Category:            finding.CatBusinessFlow,
		AccessObserved:      true,
		IdentityDistinct:    true,
		FlowStateKnown:      true,
		FlowPolicyKnown:     true,
		NegativeControlDone: true,
		RepeatOK:            true,
		EvidencePersisted:   true,
	}
}

// TestPolicyBusinessFlowEveryMissingPrerequisiteBlocksConfirmation proves the
// §29 flow battery is individually enforced and complete.
func TestPolicyBusinessFlowEveryMissingPrerequisiteBlocksConfirmation(t *testing.T) {
	tests := []struct {
		name         string
		mutator      func(*Candidate)
		wantFragment string
	}{
		{"side effect not validated", func(c *Candidate) { c.AccessObserved = false }, "side effect"},
		{"same identity", func(c *Candidate) {
			c.IdentityDistinct = false
			c.IdentitySameIdentity = true
		}, "SAME identity"},
		{"identity unverified", func(c *Candidate) {
			c.IdentityDistinct = false
			c.IdentityUnverified = true
		}, "distinctness could not be verified"},
		{"flow state unknown", func(c *Candidate) { c.FlowStateKnown = false }, "workflow state"},
		{"flow policy unknown", func(c *Candidate) { c.FlowPolicyKnown = false }, "policy"},
		{"negative control did not execute", func(c *Candidate) { c.NegativeControlDone = false }, "negative control"},
		{"repeatability failed", func(c *Candidate) { c.RepeatOK = false }, "repeatability"},
		{"evidence not persisted", func(c *Candidate) { c.EvidencePersisted = false }, "evidence"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := fullFlow()
			tc.mutator(&c)
			state, reason := c.Evaluate()
			wantState := finding.StateSuspected
			if !c.AccessObserved {
				wantState = finding.StateRejected
			}
			if state != wantState {
				t.Fatalf("state = %s, want %s; reason: %s", state, wantState, reason)
			}
			if !strings.Contains(reason, tc.wantFragment) {
				t.Fatalf("reason %q does not mention %q", reason, tc.wantFragment)
			}
		})
	}

	// The complete flow candidate confirms WITHOUT ownership or cache/public
	// probes — those controls are replaced by flow-state and policy evidence
	// (documented in blockedBusinessFlow).
	c := fullFlow()
	c.OwnerState = ownership.StateUnknown
	if state, reason := c.Evaluate(); state != finding.StateConfirmed {
		t.Fatalf("complete flow candidate blocked: %s", reason)
	}
}

// TestPolicyUnknownCategoryUsesObjectBattery proves the fail-closed default:
// an empty or unknown category routes to the strictest (object-level)
// battery, so a misrouted candidate can never confirm with a weaker set.
func TestPolicyUnknownCategoryUsesObjectBattery(t *testing.T) {
	for _, cat := range []finding.Category{"", "mystery_category"} {
		c := fullCandidate()
		c.Category = cat
		if state, _ := c.Evaluate(); state != finding.StateConfirmed {
			t.Fatalf("full object candidate with category %q must confirm", cat)
		}
		c.OwnerFloorMet = false
		if state, reason := c.Evaluate(); state != finding.StateSuspected || !strings.Contains(reason, "floor") {
			t.Fatalf("unknown category %q must route to the object battery (floor required): state=%s reason=%s", cat, state, reason)
		}
	}
}
