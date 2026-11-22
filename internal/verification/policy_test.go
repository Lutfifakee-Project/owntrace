package verification

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
)

// fullCandidate returns a candidate with every mandatory prerequisite
// satisfied — the only shape that may confirm.
func fullCandidate() Candidate {
	return Candidate{
		AccessObserved:      true,
		IdentityDistinct:    true,
		OwnerBaselineOK:     true,
		ResourceIdentityOK:  true,
		NegativeControlDone: true,
		PublicProbeDone:     true,
		CacheAnalysisDone:   true,
		RepeatOK:            true,
		OwnerState:          ownership.StateDeclared,
		OwnerFloorMet:       true,
		EvidencePersisted:   true,
	}
}

// TestPolicyEveryMissingPrerequisiteBlocksConfirmation is the §4.3 gate
// proof: removing ANY single mandatory prerequisite blocks CONFIRMED, with
// a reason that names the broken control.
func TestPolicyEveryMissingPrerequisiteBlocksConfirmation(t *testing.T) {
	tests := []struct {
		name         string
		mutator      func(*Candidate)
		wantFragment string
	}{
		{"access not observed", func(c *Candidate) { c.AccessObserved = false }, "protected data"},
		{"same identity", func(c *Candidate) {
			c.IdentityDistinct = false
			c.IdentitySameIdentity = true
		}, "SAME identity"},
		{"identity unverified (no probes)", func(c *Candidate) {
			c.IdentityDistinct = false
			c.IdentityUnverified = true
		}, "distinctness could not be verified"},
		{"owner baseline missing", func(c *Candidate) { c.OwnerBaselineOK = false }, "owner baseline"},
		{"resource identity missing", func(c *Candidate) { c.ResourceIdentityOK = false }, "object identity"},
		{"negative control did not execute", func(c *Candidate) { c.NegativeControlDone = false }, "negative control"},
		{"public probe did not execute", func(c *Candidate) { c.PublicProbeDone = false }, "public-content probe"},
		{"cache analysis did not run", func(c *Candidate) { c.CacheAnalysisDone = false }, "cache analysis"},
		{"repeatability failed", func(c *Candidate) { c.RepeatOK = false }, "repeatability"},
		{"inferred ownership", func(c *Candidate) { c.OwnerState = ownership.StateInferred }, "inferred"},
		{"unknown ownership", func(c *Candidate) { c.OwnerState = ownership.StateUnknown }, "unknown"},
		{"ownership below configured floor", func(c *Candidate) { c.OwnerFloorMet = false }, "confirmation floor"},
		{"evidence not persisted", func(c *Candidate) { c.EvidencePersisted = false }, "evidence"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := fullCandidate()
			tc.mutator(&c)
			state, reason := c.Evaluate()
			if state == finding.StateConfirmed {
				t.Fatalf("CONFIRMED emitted despite missing prerequisite %q", tc.name)
			}
			if !strings.Contains(reason, tc.wantFragment) {
				t.Fatalf("reason %q does not explain the blocker (want fragment %q)", reason, tc.wantFragment)
			}
		})
	}
}

// TestPolicyConfirmedOnlyWhenComplete proves the all-prerequisites shape
// confirms, and that an observed-access candidate with unmet prerequisites
// degrades to SUSPECTED (the access WAS observed), while a no-access
// candidate is REJECTED.
func TestPolicyConfirmedOnlyWhenComplete(t *testing.T) {
	state, reason := fullCandidate().Evaluate()
	if state != finding.StateConfirmed {
		t.Fatalf("complete candidate must confirm, got %s: %s", state, reason)
	}

	c := fullCandidate()
	c.CacheAnalysisDone = false
	state, reason = c.Evaluate()
	if state != finding.StateSuspected {
		t.Fatalf("observed access with unmet prerequisite must be SUSPECTED, got %s", state)
	}
	if !strings.Contains(reason, "cache analysis") {
		t.Fatalf("reason must name the missing control: %s", reason)
	}

	c = fullCandidate()
	c.AccessObserved = false
	state, _ = c.Evaluate()
	if state != finding.StateRejected {
		t.Fatalf("no-access candidate must be REJECTED, got %s", state)
	}
}

// TestPolicyOwnershipFloorIsInvariant verifies §4.2 at the policy level:
// inferred and unknown ownership can never support confirmation, and no
// configuration input participates in this decision.
func TestPolicyOwnershipFloorIsInvariant(t *testing.T) {
	for _, s := range []ownership.State{ownership.StateInferred, ownership.StateUnknown} {
		c := fullCandidate()
		c.OwnerState = s
		if state, _ := c.Evaluate(); state == finding.StateConfirmed {
			t.Fatalf("ownership state %q must never confirm", s)
		}
	}
	for _, s := range []ownership.State{ownership.StateConfirmed, ownership.StateDeclared} {
		c := fullCandidate()
		c.OwnerState = s
		if state, _ := c.Evaluate(); state != finding.StateConfirmed {
			t.Fatalf("ownership state %q with all prerequisites must confirm, got %s", s, state)
		}
	}
}
