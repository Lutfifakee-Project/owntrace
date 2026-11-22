package ownership

import (
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
)

func TestAllowedForConfirmedInvariant(t *testing.T) {
	// §4.2: inferred and unknown ownership must NEVER support confirmation,
	// regardless of any configuration.
	if AllowedForConfirmed(StateInferred) {
		t.Fatal("inferred ownership must not support CONFIRMED")
	}
	if AllowedForConfirmed(StateUnknown) {
		t.Fatal("unknown ownership must not support CONFIRMED")
	}
	if !AllowedForConfirmed(StateConfirmed) || !AllowedForConfirmed(StateDeclared) {
		t.Fatal("confirmed and declared ownership must support CONFIRMED")
	}
}

func TestUpsertMergesWithStateRanking(t *testing.T) {
	reg := NewRegistry()
	base := &Record{
		Resource: "order", Identifier: "o-1001", OwnerProfile: "userA",
		State: StateInferred, Confidence: 0.6, EndpointPath: "http://x/orders/o-1001",
		Provenance: []endpoints.SourceRef{{Kind: endpoints.SourceHAR, Location: "traffic"}},
		CreatedAt:  time.Now().UTC(),
	}
	first := reg.Upsert(base)
	if first.State != StateInferred {
		t.Fatalf("initial state: %s", first.State)
	}
	// A weaker (unknown) record must not downgrade the state.
	reg.Upsert(&Record{Resource: "order", Identifier: "o-1001", OwnerProfile: "userB",
		State: StateUnknown, Confidence: 0.1, CreatedAt: time.Now().UTC()})
	got, ok := reg.Lookup("order", "o-1001", "")
	if !ok {
		t.Fatal("record lost")
	}
	if got.State != StateInferred {
		t.Fatalf("state downgraded by weaker record: %s", got.State)
	}
	if got.OwnerProfile != "userA" {
		t.Fatalf("owner changed by weaker record: %s", got.OwnerProfile)
	}
	// Confidence must not decrease (same coordinates: resource+identifier+path).
	reg.Upsert(&Record{Resource: "order", Identifier: "o-1001", OwnerProfile: "userA",
		State: StateInferred, Confidence: 0.9, EndpointPath: "http://x/orders/o-1001", CreatedAt: time.Now().UTC()})
	got, _ = reg.Lookup("order", "o-1001", "")
	if got.Confidence != 0.9 {
		t.Fatalf("confidence did not keep maximum: %v", got.Confidence)
	}
	// Provenance merges without duplication.
	reg.Upsert(&Record{Resource: "order", Identifier: "o-1001", OwnerProfile: "userA",
		State: StateInferred, Confidence: 0.9, EndpointPath: "http://x/orders/o-1001",
		Provenance: []endpoints.SourceRef{{Kind: endpoints.SourceHAR, Location: "traffic"},
			{Kind: endpoints.SourceConfig, Location: "declared"}},
		CreatedAt: time.Now().UTC()})
	got, _ = reg.Lookup("order", "o-1001", "")
	if len(got.Provenance) != 2 {
		t.Fatalf("provenance merge wrong: %+v", got.Provenance)
	}
}

func TestUpsertStateEscalation(t *testing.T) {
	reg := NewRegistry()
	reg.Upsert(&Record{Resource: "doc", Identifier: "d-1", OwnerProfile: "userA",
		State: StateInferred, CreatedAt: time.Now().UTC()})
	got, _ := reg.Lookup("doc", "d-1", "")
	if got.State != StateInferred {
		t.Fatal("setup failed")
	}
	reg.Upsert(&Record{Resource: "doc", Identifier: "d-1", OwnerProfile: "userA",
		State: StateDeclared, CreatedAt: time.Now().UTC()})
	got, _ = reg.Lookup("doc", "d-1", "")
	if got.State != StateDeclared {
		t.Fatalf("declared should outrank inferred: %s", got.State)
	}
}

func TestByProfileAndOtherProfiles(t *testing.T) {
	reg := NewRegistry()
	reg.Upsert(&Record{Resource: "a", Identifier: "1", OwnerProfile: "userA", State: StateDeclared, CreatedAt: time.Now().UTC()})
	reg.Upsert(&Record{Resource: "b", Identifier: "2", OwnerProfile: "userB", State: StateDeclared, CreatedAt: time.Now().UTC()})
	reg.Upsert(&Record{Resource: "c", Identifier: "3", OwnerProfile: "userA", State: StateDeclared, CreatedAt: time.Now().UTC()})

	if got := len(reg.ByProfile("userA")); got != 2 {
		t.Fatalf("ByProfile userA: %d", got)
	}
	others := reg.ObjectsOfOtherProfiles("userA")
	if len(others) != 1 || others[0].OwnerProfile != "userB" {
		t.Fatalf("ObjectsOfOtherProfiles: %+v", others)
	}
	if len(reg.List()) != 3 {
		t.Fatalf("List: %d", len(reg.List()))
	}
}

func TestRedactedIdentifier(t *testing.T) {
	r := &Record{Identifier: "o-1001"}
	if r.RedactedIdentifier() != "o-1001" {
		t.Fatal("short identifier should pass through")
	}
	r = &Record{Identifier: "8f2a1b9c8d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"}
	if r.RedactedIdentifier() == r.Identifier {
		t.Fatal("long opaque identifier must be masked")
	}
	if !startsWith(r.RedactedIdentifier(), "obj_") {
		t.Fatalf("masked identifier format: %s", r.RedactedIdentifier())
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
