package endpoints

import (
	"testing"
)

func TestLooksIdentifierLike(t *testing.T) {
	yes := []string{"123", "o-1001", "inv-2001", "f-9", "550e8400-e29b-41d4-a716-446655440000",
		"deadbeefdeadbeef", "a1b2c3d4e5f6", "tok-oPaQue-9f2xyz"}
	no := []string{"orders", "me", "admin", "v1", "notes", "", "health", "2024-annual-report"}
	for _, s := range yes {
		if !LooksIdentifierLike(s) {
			t.Errorf("%q should look like an identifier", s)
		}
	}
	for _, s := range no {
		if LooksIdentifierLike(s) {
			t.Errorf("%q should NOT look like an identifier", s)
		}
	}
}

func TestBuildFromURLTemplatesIdentifiers(t *testing.T) {
	ep, ok := BuildFromURL("GET", "https://api.test/api/v1/orders/o-1001", SourceURL, "test")
	if !ok {
		t.Fatal("build failed")
	}
	if ep.Path != "/api/v1/orders/{order_id}" {
		t.Fatalf("path not templated: %q", ep.Path)
	}
	if ep.Host != "https://api.test" {
		t.Fatalf("host wrong: %q", ep.Host)
	}
	if len(ep.Query) != 1 || ep.Query[0].In != "path" || ep.Query[0].Example != "o-1001" {
		t.Fatalf("path param not recorded: %+v", ep.Query)
	}
}

func TestSetDeduplication(t *testing.T) {
	set := NewSet()
	e1, _ := BuildFromURL("GET", "https://api.test/api/orders/o-1001", SourceHAR, "a")
	e2, _ := BuildFromURL("GET", "https://api.test/api/orders/o-1002", SourceHAR, "b")
	p1, _ := set.Add(e1)
	p2, isNew := set.Add(e2)
	if set.Len() != 1 {
		t.Fatalf("expected 1 deduped endpoint, got %d", set.Len())
	}
	if isNew {
		t.Fatal("second identical-shape URL should merge")
	}
	if len(p1.Samples) != 2 {
		t.Fatalf("samples not merged: %v", p1.Samples)
	}
	if p1 != p2 {
		t.Fatal("merged endpoint identity mismatch")
	}
}

func TestSetKeepsStructuralVariants(t *testing.T) {
	set := NewSet()
	e1, _ := BuildFromURL("GET", "https://api.test/api/orders/o-1001", SourceHAR, "a")
	e2, _ := BuildFromURL("GET", "https://api.test/api/orders/o-1001/notes", SourceHAR, "b")
	set.Add(e1)
	set.Add(e2)
	if set.Len() != 2 {
		t.Fatalf("structural variants must remain distinct, got %d", set.Len())
	}
}

func TestFillURL(t *testing.T) {
	ep, _ := BuildFromURL("GET", "https://api.test/api/tenants/t-acme/files/f-9001", SourceURL, "t")
	u, missing, err := ep.FillURL(map[string]string{})
	if err != nil || len(missing) > 0 {
		t.Fatalf("fill failed: %v %v", err, missing)
	}
	if u != "https://api.test/api/tenants/t-acme/files/f-9001" {
		t.Fatalf("fill URL wrong: %s", u)
	}
}

func TestPathParamName(t *testing.T) {
	if n := PathParamName("orders", "o-1001"); n != "order_id" {
		t.Fatalf("got %q", n)
	}
	if n := PathParamName("users", "550e8400-e29b-41d4-a716-446655440000"); n != "user_uuid" {
		t.Fatalf("uuid naming got %q", n)
	}
}

func TestAdminDetection(t *testing.T) {
	ep, _ := BuildFromURL("GET", "https://api.test/api/admin/stats", SourceHAR, "x")
	if !ep.Adminish {
		t.Fatal("admin path not flagged")
	}
}
