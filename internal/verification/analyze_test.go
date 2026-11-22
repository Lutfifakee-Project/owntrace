package verification

import (
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
)

func TestContainsIdentifier(t *testing.T) {
	yes := [][2]string{
		{`{"order":{"id":"o-1001"}}`, "o-1001"},
		{`{"id": 1001, "name": "x"}`, "1001"},
		{`{"id":"550E8400-E29B-41D4-A716-446655440000"}`, "550e8400-e29b-41d4-a716-446655440000"},
	}
	no := [][2]string{
		{`{"id": 10011}`, "1001"}, // substring of a larger number
		{`{"id": 21001}`, "1001"}, // embedded digits
		{`{"other": "x"}`, "o-1001"},
		{``, "1"},
	}
	for _, c := range yes {
		if !containsIdentifier(c[0], c[1]) {
			t.Errorf("should contain %s: %s", c[1], c[0])
		}
	}
	for _, c := range no {
		if containsIdentifier(c[0], c[1]) {
			t.Errorf("should NOT contain %s: %s", c[1], c[0])
		}
	}
}

func TestSimilarity(t *testing.T) {
	a := `{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`
	b := `{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`
	c := `{"error":"not found"}`
	if jaccardSimilarity(a, b) < 0.99 {
		t.Error("identical bodies not similar")
	}
	if jaccardSimilarity(a, c) > 0.3 {
		t.Error("unrelated bodies too similar")
	}
}

func TestDataFieldOverlap(t *testing.T) {
	owner := `{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`
	same := `{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`
	echo := `{"requested":"o-1001","echo":"generic-content-not-object-data"}`
	ov1, n1 := dataFieldOverlap(owner, same)
	if ov1 < 0.99 || n1 < 3 {
		t.Errorf("full object overlap wrong: %v %d", ov1, n1)
	}
	ov2, n2 := dataFieldOverlap(owner, echo)
	if ov2 > 0.5 {
		t.Errorf("echo overlap too high: %.2f of %d", ov2, n2)
	}
}

func TestMutatedIdentifier(t *testing.T) {
	if mutatedIdentifier("1001") == "1001" {
		t.Error("numeric mutation unchanged")
	}
	if mutatedIdentifier("550e8400-e29b-41d4-a716-446655440000") ==
		"550e8400-e29b-41d4-a716-446655440000" {
		t.Error("uuid mutation unchanged")
	}
	m := mutatedIdentifier("o-1001")
	if m == "o-1001" || !contains("o-1001", m) {
		t.Errorf("opaque mutation odd: %q", m)
	}
}

func contains(s, sub string) bool {
	return len(sub) > len(s) && sub[:len(s)] == s
}

func TestClassifyMatrix(t *testing.T) {
	e := &Engine{Cfg: config.Verification{Repeats: 1}}
	item := TestItem{Identifier: "o-1001", URL: "http://api.test/api/orders/o-1001", Resource: "order"}
	owner := ex(200, `{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`)
	neg := ex(404, `{"error":"not found"}`)

	// protected: 403
	att := ex(403, `{"error":"forbidden"}`)
	st, _, _ := e.classify(item, owner, att, neg, "bob")
	if st != finding.StateRejected {
		t.Errorf("403 should reject, got %s", st)
	}

	// protected: 404 generic matching negative control
	att = ex(404, `{"error":"not found"}`)
	st, _, _ = e.classify(item, owner, att, neg, "bob")
	if st != finding.StateRejected {
		t.Errorf("generic 404 should reject, got %s", st)
	}

	// vulnerable: full object data
	att = ex(200, `{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`)
	st, _, _ = e.classify(item, owner, att, neg, "bob")
	if st != finding.StateConfirmed {
		t.Errorf("full data should confirm, got %s", st)
	}

	// decoy: 200 + echoed id, no data fields
	att = ex(200, `{"requested":"o-1001","echo":"generic"}`)
	st, _, _ = e.classify(item, owner, att, neg, "bob")
	if st == finding.StateConfirmed {
		t.Errorf("echo decoy must not confirm, got %s", st)
	}

	// soft-404 decoy endpoint: 200 with same generic body for nonexistent id
	att = ex(200, `{"page":"marketing","greeting":"hello visitor"}`)
	neg = ex(200, `{"page":"marketing","greeting":"hello visitor"}`)
	st, _, _ = e.classify(item, owner, att, neg, "bob")
	if st != finding.StateRejected {
		t.Errorf("decoy endpoint (200 for nonexistent) must reject, got %s", st)
	}

	// empty 200
	att = ex(200, ``)
	st, _, _ = e.classify(item, owner, att, ex(404, `{"error":"x"}`), "bob")
	if st != finding.StateRejected {
		t.Errorf("empty 200 must reject, got %s", st)
	}

	// listing instead of the object: 200 without identifier
	att = ex(200, `{"orders":[{"id":"o-5555"},{"id":"o-6666"}]}`)
	st, _, _ = e.classify(item, owner, att, ex(404, `{"error":"x"}`), "bob")
	if st == finding.StateConfirmed {
		t.Errorf("unrelated listing must not confirm, got %s", st)
	}
}

func TestUnknownOwnershipCannotConfirm(t *testing.T) {
	e := &Engine{Cfg: config.Verification{MinOwnerStateForConfirmed: "declared", Repeats: 1, RequireIdentitySeparation: false}}
	item := TestItem{Identifier: "o-1001", URL: "http://api.test/api/orders/o-1001",
		Resource: "order", Owner: "userA", OwnerState: ownership.StateUnknown, Category: finding.CatHorizontal}
	owner := ex(200, `{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`)
	att := ex(200, `{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`)
	st, _, _ := e.classify(item, owner, att, ex(404, `{"error":"not found"}`), "bob")
	if st != finding.StateConfirmed {
		t.Fatalf("classify should confirm (gate tested separately), got %s", st)
	}
	// The engine gate: unknown ownership downgrades.
	if ownership.AllowedForConfirmed(ownership.StateUnknown) {
		t.Fatal("unknown ownership allowed for confirmation")
	}
	if !ownerStateMeetsFloor(ownership.StateConfirmed, "declared") {
		t.Fatal("confirmed ownership should meet declared floor")
	}
	if ownerStateMeetsFloor(ownership.StateInferred, "declared") {
		t.Fatal("inferred ownership must not meet declared floor")
	}
}

func TestDenialClassification(t *testing.T) {
	if classifyDenial(401, "") != denialAuth || classifyDenial(403, "") != denialAuth {
		t.Error("401/403 not classified as auth denial")
	}
	if classifyDenial(404, "") != denialNotFound {
		t.Error("404 not classified as not-found")
	}
	if classifyDenial(200, `{"error":"not found"}`) != denialNotFound {
		t.Error("soft 404 not detected")
	}
	if classifyDenial(200, `{"data":"x"}`) != denialNone {
		t.Error("normal 200 classified as denial")
	}
}
