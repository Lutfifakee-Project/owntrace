package scope

import (
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
)

func testScope() config.Scope {
	return config.Scope{
		Targets: []config.ScopeTarget{
			{
				Host:           "api.example.com",
				Schemes:        []string{"https"},
				IncludePaths:   []string{"/api/"},
				ExcludePaths:   []string{"/api/admin"},
				AllowedMethods: []string{"GET"},
				MaxRequests:    3,
			},
		},
		GlobalAllowedMethods: []string{"GET", "HEAD"},
		MaxRequestsTotal:     5,
	}
}

func TestDenyByDefault(t *testing.T) {
	c, err := New(testScope())
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Check("GET", "http://evil.example.com/api/x"); d.Allowed {
		t.Fatal("unconfigured host allowed")
	}
	if d := c.Check("GET", "https://api.example.com/web/x"); d.Allowed {
		t.Fatal("path outside include patterns allowed")
	}
}

func TestPathAndSchemeRules(t *testing.T) {
	c, _ := New(testScope())
	if d := c.Check("GET", "https://api.example.com/api/orders/1"); !d.Allowed {
		t.Fatalf("in-scope request denied: %s", d.Reason)
	}
	if d := c.Check("GET", "https://api.example.com/api/admin/users"); d.Allowed {
		t.Fatal("excluded path allowed")
	}
	if d := c.Check("GET", "http://api.example.com/api/orders/1"); d.Allowed {
		t.Fatal("http not in schemes but allowed")
	}
	if d := c.Check("POST", "https://api.example.com/api/orders"); d.Allowed {
		t.Fatal("POST not allowed by target or global")
	}
}

func TestSubdomainsNotAutoAuthorized(t *testing.T) {
	c, _ := New(testScope())
	if d := c.Check("GET", "https://v2.api.example.com/api/x"); d.Allowed {
		t.Fatal("subdomain auto-authorized without opt-in")
	}
	cfg := testScope()
	cfg.AllowSubdomains = true
	c2, _ := New(cfg)
	if d := c2.Check("GET", "https://v2.api.example.com/api/x"); !d.Allowed {
		t.Fatalf("subdomain denied with opt-in: %s", d.Reason)
	}
}

func TestBlockedDestructivePatterns(t *testing.T) {
	cfg := testScope()
	cfg.BlockedPathPatterns = config.DefaultBlockedPatterns()
	c, _ := New(cfg)
	if d := c.Check("GET", "https://api.example.com/api/orders/1/delete"); d.Allowed {
		t.Fatal("destructive-matching path allowed")
	}
	if d := c.Check("GET", "https://api.example.com/api/payment-callback"); d.Allowed {
		t.Fatal("payment path allowed")
	}
}

func TestRequestBudgets(t *testing.T) {
	c, _ := New(testScope())
	for i := 0; i < 3; i++ {
		if d := c.CountRequest("https://api.example.com/api/x"); !d.Allowed {
			t.Fatalf("request %d denied early: %s", i+1, d.Reason)
		}
	}
	if d := c.CountRequest("https://api.example.com/api/x"); d.Allowed {
		t.Fatal("per-target budget not enforced")
	}
	if d := c.CountRequest("https://api.example.com/api/y"); d.Allowed {
		t.Fatal("total budget not enforced after per-target")
	}
}

func TestRedirectValidation(t *testing.T) {
	c, _ := New(testScope())
	if d := c.CheckURL("https://api.example.com/api/login?next=http://evil.example.com"); !d.Allowed {
		t.Fatalf("target URL should be allowed: %s", d.Reason)
	}
	// The redirect DESTINATION is what gets validated hop-by-hop:
	if d := c.CheckURL("http://evil.example.com/steal"); d.Allowed {
		t.Fatal("out-of-scope redirect destination allowed")
	}
}

func TestUnparseableAndSpecialURLs(t *testing.T) {
	c, _ := New(testScope())
	for _, u := range []string{"file:///etc/passwd", "gopher://x", "::::", "https://user:pass@api.example.com/api/x"} {
		if d := c.Check("GET", u); d.Allowed {
			t.Errorf("dangerous URL allowed: %s", u)
		}
	}
}

func TestInvalidRegexFailsFast(t *testing.T) {
	cfg := testScope()
	cfg.BlockedPathPatterns = []string{"([unclosed"}
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid regex accepted")
	}
}

func TestRootInclude(t *testing.T) {
	cfg := testScope()
	cfg.Targets[0].IncludePaths = []string{"/"}
	c, _ := New(cfg)
	if d := c.Check("GET", "https://api.example.com/anything/here"); !d.Allowed {
		t.Fatalf("root include failed: %s", d.Reason)
	}
}
