package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/mockapp"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

func TestParseHAR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.har")
	har := `{"log":{"version":"1.2","creator":{"name":"test"},"entries":[
		{"request":{"method":"GET","url":"https://api.test/api/v1/orders/o-1001",
			"headers":[{"name":"Authorization","value":"Bearer sekrit"},{"name":"X-Owntrace-Profile","value":"userA"}]},
		 "response":{"status":200,"content":{"mimeType":"application/json","text":"{\"order\":{\"id\":\"o-1001\"}}"}}},
		{"request":{"method":"POST","url":"https://api.test/api/v1/orders",
			"postData":{"mimeType":"application/json","text":"{\"item\":\"x\",\"secret\":\"s3cr3t\"}"}},
		 "response":{"status":201,"content":{"mimeType":"application/json","text":"{}"}}},
		{"request":{"method":"","url":""}}
	]}}`
	if err := os.WriteFile(path, []byte(har), 0o600); err != nil {
		t.Fatal(err)
	}
	res := NewResult()
	if err := ParseHAR(path, "X-Owntrace-Profile", res); err != nil {
		t.Fatal(err)
	}
	if res.Endpoints.Len() != 2 {
		t.Fatalf("expected 2 endpoints, got %d (notes: %v)", res.Endpoints.Len(), res.Notes)
	}
	eps := res.Endpoints.List()
	found := false
	for _, ep := range eps {
		if strings.HasPrefix(ep.Path, "/api/v1/orders/{order_id}") && ep.Method == "GET" {
			found = true
			if ep.Auth != "bearer" {
				t.Errorf("auth not derived from HAR: %q", ep.Auth)
			}
			for _, h := range ep.Sources {
				if h.Kind != endpoints.SourceHAR {
					t.Errorf("provenance wrong: %+v", h)
				}
			}
		}
	}
	if !found {
		t.Fatal("templated orders endpoint not found")
	}
	if len(res.Samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(res.Samples))
	}
	if res.Samples[0].Profile != "userA" {
		t.Errorf("profile attribution failed: %+v", res.Samples[0])
	}
	// credentials must not be stored in endpoint structures
	for _, ep := range eps {
		for _, p := range ep.Headers {
			if strings.Contains(p.Example, "sekrit") {
				t.Error("credential leaked into parsed endpoint")
			}
		}
	}
}

func TestParseHARMalformed(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.har")
	_ = os.WriteFile(bad, []byte(`{"log":{"entries":[{"request":{"method":"GET","url":123}}]}}`), 0o600)
	res := NewResult()
	if err := ParseHAR(bad, "", res); err != nil && !strings.Contains(err.Error(), "parse HAR") {
		// either a parse error (fine) or tolerated entries (fine); panics are not
		t.Fatalf("unexpected: %v", err)
	}
	garbage := filepath.Join(dir, "garbage.har")
	_ = os.WriteFile(garbage, []byte(`this is not json {{{`), 0o600)
	res2 := NewResult()
	if err := ParseHAR(garbage, "", res2); err == nil {
		t.Fatal("garbage HAR accepted")
	}
}

const openAPISpec = `{
  "openapi": "3.0.0",
  "info": {"title": "Test", "version": "1"},
  "servers": [{"url": "https://api.test/api/v1"}],
  "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
  "paths": {
    "/orders/{orderId}": {
      "get": {
        "operationId": "getOrder",
        "parameters": [
          {"name": "orderId", "in": "path", "required": true, "schema": {"type": "string", "example": "o-1001"}},
          {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
        ],
        "security": [{"bearerAuth": []}],
        "responses": {"200": {"description": "ok"}}
      },
      "post": {
        "operationId": "createOrder",
        "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/OrderInput"}}}},
        "responses": {"201": {"description": "created"}}
      }
    },
    "/admin/stats": {"get": {"operationId": "stats", "responses": {"200": {"description": "ok"}}}}
  },
  "components": {
    "schemas": {"OrderInput": {"type": "object", "properties": {"item": {"type": "string"}, "qty": {"type": "integer"}}}}
  }
}`

func TestParseOpenAPI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(path, []byte(openAPISpec), 0o600); err != nil {
		t.Fatal(err)
	}
	res := NewResult()
	if err := ParseOpenAPI(path, res); err != nil {
		t.Fatal(err)
	}
	eps := res.Endpoints.List()
	if res.Endpoints.Len() != 3 {
		t.Fatalf("expected 3 endpoints (2x orders + admin), got %d: %+v", res.Endpoints.Len(), eps)
	}
	for _, ep := range eps {
		switch ep.Path {
		case "/orders/{orderId}":
			if ep.Method == "GET" {
				if ep.Auth != "bearer" {
					t.Errorf("security scheme not mapped: %q", ep.Auth)
				}
				if ep.PathParams() == nil || len(ep.PathParams()) != 1 || ep.PathParams()[0] != "orderId" {
					t.Errorf("path param missing: %+v", ep.Query)
				}
			}
			if ep.Method == "POST" {
				if ep.Body == nil || ep.Body.Template == "" || !strings.Contains(ep.Body.Template, "item") {
					t.Errorf("body template not synthesized from $ref schema: %+v", ep.Body)
				}
			}
		case "/admin/stats":
			if !ep.Adminish {
				t.Error("admin path not flagged")
			}
		}
	}
}

const swaggerSpec = `{
  "swagger": "2.0",
  "info": {"title": "Legacy", "version": "1"},
  "host": "legacy.test",
  "basePath": "/v2",
  "schemes": ["https"],
  "securityDefinitions": {"api_key": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
  "paths": {
    "/things/{id}": {
      "get": {
        "parameters": [{"$ref": "#/parameters/ID"}],
        "security": [{"api_key": []}],
        "responses": {"200": {"description": "ok"}}
      }
    }
  },
  "parameters": {"ID": {"name": "id", "in": "path", "required": true, "type": "string"}}
}`

func TestParseSwagger2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "swagger.json")
	_ = os.WriteFile(path, []byte(swaggerSpec), 0o600)
	res := NewResult()
	if err := ParseOpenAPI(path, res); err != nil {
		t.Fatal(err)
	}
	if res.Endpoints.Len() != 1 {
		t.Fatalf("expected 1 endpoint, got %d", res.Endpoints.Len())
	}
	ep := res.Endpoints.List()[0]
	if ep.Host != "https://legacy.test/v2" {
		t.Errorf("swagger base URL wrong: %q", ep.Host)
	}
	if ep.Auth != "header" {
		t.Errorf("apiKey header auth not mapped: %q", ep.Auth)
	}
	if len(ep.Query) != 1 || ep.Query[0].Name != "id" {
		t.Errorf("$ref parameter not resolved: %+v", ep.Query)
	}
}

func TestCrawlScopeBound(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	// crawler page with links
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page":
			_, _ = w.Write([]byte(`<html><body>
				<a href="/api/v1/orders/o-1001">link</a>
				<a href="https://evil.example.com/x">out</a>
				<form action="/api/v1/login" method="POST"><input name="user"></form>
				<script>fetch("/api/v1/invoices/inv-1")</script>
			</body></html>`))
		default:
			http.NotFound(w, r)
		}
	})
	crawlSrv := httptest.NewServer(mux)
	defer crawlSrv.Close()

	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: hostOf(crawlSrv.URL), IncludePaths: []string{"/"}}},
		GlobalAllowedMethods: []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}
	se, _ := safety.New(safety.Config{RatePerSecond: 50, Concurrency: 2})
	se.Scope = sc
	cl := httpclient.New(se, logger.New(logger.LevelError), 5e9, 1<<20, 5, 0)
	res := NewResult()
	Crawl(context.Background(), cl, sc, []string{crawlSrv.URL + "/page"}, 1, 10, logger.New(logger.LevelError), res)

	paths := map[string]bool{}
	for _, ep := range res.Endpoints.List() {
		paths[ep.Path] = true
	}
	if !paths["/page"] {
		t.Error("seed page not recorded")
	}
	if !paths["/api/v1/orders/{order_id}"] {
		t.Errorf("linked endpoint not found: %v", paths)
	}
	if !paths["/api/v1/invoices/{invoice_id}"] {
		t.Errorf("JS-discovered route not found: %v", paths)
	}
	for p := range paths {
		if strings.Contains(p, "evil") {
			t.Error("out-of-scope link crawled")
		}
	}
}

func hostOf(url string) string {
	u := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}
