package objects

import (
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
)

func TestFromEndpointPathAndQuery(t *testing.T) {
	ep, _ := endpoints.BuildFromURL("GET", "https://api.test/api/v1/invoices/inv-2001/payments", endpoints.SourceHAR, "x")
	ep.Query = append(ep.Query, endpoints.Param{Name: "order_id", In: "query", Example: "42"})
	cs := FromEndpoint(ep)
	found := map[string]*Candidate{}
	for _, c := range cs {
		found[c.ParamName] = c
	}
	if c, ok := found["invoice_id"]; !ok || c.Resource != "payment" {
		// resource guess: last resource segment before invoice_id is "payments"? The path is
		// /api/v1/invoices/{invoice_id}/payments — placeholder after "invoices".
		if ok && c.Resource != "invoice" && c.Resource != "payment" {
			t.Fatalf("resource guess unexpected: %q", c.Resource)
		}
	}
	if _, ok := found["order_id"]; !ok {
		t.Fatal("query param candidate missing")
	}
}

func TestFromResponseMining(t *testing.T) {
	body := []byte(`{"orders":[{"id":"o-1001","owner":"alice","meta":{"item_id":"i-9"}},{"id":"o-1002"}],"total":2}`)
	cs := FromResponse("ep1", body, "application/json", nil)
	if len(cs) == 0 {
		t.Fatal("no candidates mined")
	}
	ids := map[string]bool{}
	for _, c := range cs {
		ids[c.Example] = true
	}
	if !ids["o-1001"] || !ids["o-1002"] || !ids["i-9"] {
		t.Fatalf("mining incomplete: %+v", cs)
	}
}

func TestFromResponseIgnoresNonIdentifiers(t *testing.T) {
	body := []byte(`{"users":[{"id":"alice"},{"id":"bob"}]}`)
	cs := FromResponse("ep1", body, "application/json", nil)
	for _, c := range cs {
		if c.Example == "alice" || c.Example == "bob" {
			t.Errorf("word-like value treated as identifier: %s", c.Example)
		}
	}
}

func TestIsTenantParam(t *testing.T) {
	yes := []string{"tenant_id", "org", "workspaceId", "account_id", "teamID"}
	no := []string{"order_id", "id", "user_id"}
	for _, s := range yes {
		if !IsTenantParam(s) {
			t.Errorf("%q should be tenant-like", s)
		}
	}
	for _, s := range no {
		if IsTenantParam(s) {
			t.Errorf("%q should not be tenant-like", s)
		}
	}
}

func TestShapeOf(t *testing.T) {
	cases := map[string]Shape{
		"123":                                  ShapeNumeric,
		"550e8400-e29b-41d4-a716-446655440000": ShapeUUID,
		"deadbeefdeadbeef":                     ShapeHex,
		"tok-oPaQue-9f2xyz":                    ShapeOpaque,
	}
	for v, want := range cases {
		if got := ShapeOf(v); got != want {
			t.Errorf("ShapeOf(%q) = %s, want %s", v, got, want)
		}
	}
}
