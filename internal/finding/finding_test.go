package finding_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/finding"
)

func TestStateTransitionsHappyPath(t *testing.T) {
	f := &finding.Finding{ID: "F-1", State: finding.StateDiscovered}
	steps := []struct {
		to     finding.State
		reason string
	}{
		{finding.StateCandidate, "candidate identified"},
		{finding.StateTesting, "controls started"},
		{finding.StateConfirmed, "all prerequisites satisfied"},
	}
	for _, s := range steps {
		if err := f.Transition(s.to, s.reason, "EV-1"); err != nil {
			t.Fatalf("transition to %s: %v", s.to, err)
		}
	}
	if f.State != finding.StateConfirmed {
		t.Fatalf("final state: %s", f.State)
	}
	if len(f.Transitions) != 3 {
		t.Fatalf("transition history: %d", len(f.Transitions))
	}
	if f.Transitions[0].From != finding.StateDiscovered || f.Transitions[2].To != finding.StateConfirmed {
		t.Fatalf("transition chain wrong: %+v", f.Transitions)
	}
	if f.Transitions[2].EvidenceID != "EV-1" {
		t.Fatal("evidence not linked to transition")
	}
	if f.Transitions[0].At.IsZero() {
		t.Fatal("transition timestamp missing")
	}
}

func TestTerminalStatesRejectFurtherTransitions(t *testing.T) {
	for _, terminal := range []finding.State{finding.StateConfirmed, finding.StateSuspected,
		finding.StateInconclusive, finding.StateRejected, finding.StateError} {
		f := &finding.Finding{ID: "F-1", State: terminal, UpdatedAt: time.Now()}
		// Transitioning to a DIFFERENT state from a terminal state must fail.
		for _, to := range []finding.State{finding.StateConfirmed, finding.StateSuspected,
			finding.StateRejected, finding.StateError} {
			if to == terminal {
				continue
			}
			if err := f.Transition(to, "attempt to leave terminal state", ""); err == nil {
				t.Fatalf("terminal state %s accepted a transition to %s", terminal, to)
			}
		}
		// Same-state transition is a no-op, not an error.
		if err := f.Transition(terminal, "same", ""); err != nil {
			t.Fatalf("same-state transition errored for %s: %v", terminal, err)
		}
	}
}

func TestAddControlAndControlStatus(t *testing.T) {
	f := &finding.Finding{ID: "F-1"}
	f.AddControl(finding.Control{Name: finding.ControlOwnerBaseline, Status: finding.StatusPass, EvidenceID: "EV-9"})
	f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: finding.StatusFail})
	if got := f.ControlStatus(finding.ControlOwnerBaseline); got != finding.StatusPass {
		t.Fatalf("owner baseline status: %s", got)
	}
	if got := f.ControlStatus(finding.ControlRepeatability); got != finding.StatusFail {
		t.Fatalf("repeatability status: %s", got)
	}
	if got := f.ControlStatus("nonexistent"); got != "" {
		t.Fatalf("missing control status: %q", got)
	}
	if len(f.EvidenceIDs) != 1 || f.EvidenceIDs[0] != "EV-9" {
		t.Fatalf("evidence ids: %v", f.EvidenceIDs)
	}
}

func TestNewIDStableAndDistinct(t *testing.T) {
	a := finding.NewID("S-1", "ep-1", "horizontal_object_access", "o-1001|userA|http://x/1")
	b := finding.NewID("S-1", "ep-1", "horizontal_object_access", "o-1001|userA|http://x/1")
	c := finding.NewID("S-1", "ep-1", "horizontal_object_access", "o-1001|userA|http://x/2")
	if a != b {
		t.Fatal("same coordinates must produce the same finding ID")
	}
	if a == c {
		t.Fatal("different URLs must produce distinct finding IDs")
	}
}

func TestRedactedIdentifier(t *testing.T) {
	f := &finding.Finding{Identifier: "o-1001"}
	if f.RedactedIdentifier() != "o-1001" {
		t.Fatal("short identifier should pass through")
	}
	f = &finding.Finding{Identifier: strings.Repeat("x", 80)}
	if f.RedactedIdentifier() == f.Identifier {
		t.Fatal("long opaque identifier must be masked")
	}
	f = &finding.Finding{Identifier: "user@example.com"}
	if f.RedactedIdentifier() == "user@example.com" {
		t.Fatal("PII identifier must be masked")
	}
}

func TestDefaultRemediationCoversAllCategories(t *testing.T) {
	for _, c := range []finding.Category{finding.CatHorizontal, finding.CatVertical,
		finding.CatAnonymous, finding.CatCrossTenant, finding.CatNested} {
		if finding.DefaultRemediation(c) == "" {
			t.Fatalf("missing remediation for %s", c)
		}
	}
}
