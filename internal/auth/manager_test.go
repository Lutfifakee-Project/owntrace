package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

func newTestClientFor(t *testing.T, srv *httptest.Server) *httpclient.Client {
	t.Helper()
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: srv.Listener.Addr().String(), IncludePaths: []string{"/"}}},
		GlobalAllowedMethods: []string{"GET", "POST"},
	})
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: 100, Concurrency: 4, MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	return httpclient.New(se, logger.New(logger.LevelError), 5e9, 1<<20, 5, 0)
}

func TestHeadersPerProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Profiles = []config.Profile{
		{Name: "a", Type: "bearer", Token: "tok-a"},
		{Name: "b", Type: "header", Headers: map[string]string{"X-API-Key": "key-b"}},
		{Name: "c", Type: "basic", Username: "u", Password: "p"},
		{Name: "anon", Type: "none"},
	}
	m, err := New(cfg, logger.New(logger.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	h, err := m.Headers("a")
	if err != nil || h["Authorization"] != "Bearer tok-a" {
		t.Fatalf("bearer headers wrong: %v %v", h, err)
	}
	h2, _ := m.Headers("b")
	if h2["X-API-Key"] != "key-b" {
		t.Fatalf("header profile wrong: %v", h2)
	}
	h3, _ := m.Headers("c")
	if h3["Authorization"] == "" || len(h3["Authorization"]) < 10 {
		t.Fatalf("basic headers wrong: %v", h3)
	}
	h4, err := m.Headers("anon")
	if err != nil || len(h4) != 0 {
		t.Fatalf("anon headers wrong: %v %v", h4, err)
	}
	if _, err := m.Headers("unknown"); err == nil {
		t.Fatal("unknown profile accepted — accidental credential reuse risk")
	}
}

func TestProfileIsolation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Profiles = []config.Profile{
		{Name: "a", Type: "bearer", Token: "tok-a"},
		{Name: "b", Type: "bearer", Token: "tok-b"},
	}
	m, _ := New(cfg, logger.New(logger.LevelError))
	ha, _ := m.Headers("a")
	hb, _ := m.Headers("b")
	if ha["Authorization"] == hb["Authorization"] {
		t.Fatal("two different profiles produced identical credentials")
	}
}

func TestIdentitySeparationDistinct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer tok-a":
			_, _ = w.Write([]byte(`{"user":{"id":"usr-1"}}`))
		case "Bearer tok-b":
			_, _ = w.Write([]byte(`{"user":{"id":"usr-2"}}`))
		default:
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	cfg := &config.Config{}
	base := srv.URL
	cfg.Auth.Profiles = []config.Profile{
		{Name: "a", Type: "bearer", Token: "tok-a", Identity: config.IdentityProbe{Endpoint: base + "/me", Method: "GET", Field: "user.id"}},
		{Name: "b", Type: "bearer", Token: "tok-b", Identity: config.IdentityProbe{Endpoint: base + "/me", Method: "GET", Field: "user.id"}},
	}
	m, _ := New(cfg, logger.New(logger.LevelError))
	res := m.VerifySeparation(context.Background(), newTestClientFor(t, srv), []string{"a", "b"})
	if !res.Verified || !res.Distinct {
		t.Fatalf("expected verified distinct identities, got %+v", res)
	}
}

func TestIdentitySeparationIdentical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// BOTH tokens belong to the same underlying user (misconfiguration).
		_, _ = w.Write([]byte(`{"user":{"id":"usr-1"}}`))
	}))
	defer srv.Close()
	cfg := &config.Config{}
	base := srv.URL
	cfg.Auth.Profiles = []config.Profile{
		{Name: "a", Type: "bearer", Token: "tok-a", Identity: config.IdentityProbe{Endpoint: base + "/me", Method: "GET", Field: "user.id"}},
		{Name: "b", Type: "bearer", Token: "tok-b", Identity: config.IdentityProbe{Endpoint: base + "/me", Method: "GET", Field: "user.id"}},
	}
	m, _ := New(cfg, logger.New(logger.LevelError))
	res := m.VerifySeparation(context.Background(), newTestClientFor(t, srv), []string{"a", "b"})
	if res.Distinct {
		t.Fatalf("identical identities passed separation: %+v", res)
	}
	if res.Verified {
		t.Fatal("unverified separation reported as verified")
	}
}
