package graphql

import "testing"

func TestHarvestClassifiesAndRejects(t *testing.T) {
	op, ok := Harvest("http://x/graphql", `{"query":"mutation M($id:String!){deleteDoc(id:$id)}","variables":{"id":"doc-1"}}`, "har#0")
	if !ok || op.Kind != "mutation" || op.Variables["id"] != "doc-1" {
		t.Fatalf("mutation harvest wrong: %+v ok=%v", op, ok)
	}
	op, ok = Harvest("http://x/graphql", `{"query":"# comment\nquery Q($id:String!){node(id:$id){id}}","variables":{"id":"doc-3001"}}`, "har#1")
	if !ok || op.Kind != "query" {
		t.Fatalf("commented query harvest wrong: %+v", op)
	}
	if _, ok := Harvest("http://x/graphql", `{"not":"graphql"}`, "har#2"); ok {
		t.Fatal("non-GraphQL payload accepted")
	}
	if _, ok := Harvest("http://x/graphql", `plain text`, "har#3"); ok {
		t.Fatal("plain text accepted")
	}
	if IsGraphQLBody(`{"query":"query{ok}"}`) != true {
		t.Fatal("IsGraphQLBody missed a GraphQL body")
	}
}

func TestSwapIDReplacesEverywhere(t *testing.T) {
	vars := map[string]any{
		"id":   "doc-3001",
		"list": []any{"doc-3001", "x"},
		"nest": map[string]any{"inner": "doc-3001"},
		"num":  float64(7),
	}
	got := SwapID(vars, "doc-3001", "ot-neg-1")
	if got["id"] != "ot-neg-1" {
		t.Fatalf("top-level swap failed: %v", got["id"])
	}
	if l := got["list"].([]any); l[0] != "ot-neg-1" || l[1] != "x" {
		t.Fatalf("list swap failed: %v", l)
	}
	if n := got["nest"].(map[string]any); n["inner"] != "ot-neg-1" {
		t.Fatalf("nested swap failed: %v", n)
	}
	if got["num"] != float64(7) {
		t.Fatalf("non-string scalar mutated: %v", got["num"])
	}
	// The original variables are untouched (deep copy).
	if vars["id"] != "doc-3001" {
		t.Fatal("SwapID mutated its input")
	}
}

func TestRenderRequestKeepsVariables(t *testing.T) {
	op := Operation{Query: "query($id:String!){node(id:$id){id}}", Variables: map[string]any{"id": "doc-3001"}}
	s := RenderRequest(op)
	if !contains(s, `"variables":{"id":"doc-3001"}`) {
		t.Fatalf("rendered request lost variables: %s", s)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || index(s, sub) >= 0)
}

func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
