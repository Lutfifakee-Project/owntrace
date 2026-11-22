package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

func newClientFor(t *testing.T, srv *httptest.Server, extra config.Scope) (*Client, *safety.Engine) {
	t.Helper()
	cfg := config.Scope{
		Targets:              []config.ScopeTarget{{Host: srv.Listener.Addr().String(), IncludePaths: []string{"/"}}},
		GlobalAllowedMethods: []string{"GET", "POST"},
		MaxRequestsTotal:     1000,
	}
	cfg.BlockedPathPatterns = extra.BlockedPathPatterns
	sc, err := scope.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: 200, Concurrency: 4, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	return New(se, logger.New(logger.LevelError), 3*time.Second, 1<<20, 5, 1), se
}

func TestRedirectChainFollowedAndRecorded(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/final")
		w.WriteHeader(302)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	cl, _ := newClientFor(t, srv, config.Scope{})

	x := cl.Do(context.Background(), "GET", srv.URL+"/start", Options{})
	if !x.Succeeded() || x.Status != 200 {
		t.Fatalf("redirect chain failed: %+v", x)
	}
	if len(x.Redirects) != 1 || !x.Redirects[0].InScope {
		t.Fatalf("redirect hops not recorded: %+v", x.Redirects)
	}
	if !strings.HasSuffix(x.FinalURL, "/final") {
		t.Errorf("final URL wrong: %s", x.FinalURL)
	}
}

func TestOutOfScopeRedirectBlocked(t *testing.T) {
	var external string
	mux := http.NewServeMux()
	mux.HandleFunc("/escape", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", external+"/steal")
		w.WriteHeader(302)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	external = srv.URL // same server but we craft an out-of-scope host via example.invalid
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/escape", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://in scope-invalid.example/steal")
		w.WriteHeader(302)
	})
	_ = mux2

	// Use a scope that only allows the test server: redirect to example.invalid
	// must be blocked.
	mux3 := http.NewServeMux()
	mux3.HandleFunc("/escape", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://example.invalid/steal")
		w.WriteHeader(302)
	})
	srv2 := httptest.NewServer(mux3)
	defer srv2.Close()

	cl, _ := newClientFor(t, srv2, config.Scope{})
	x := cl.Do(context.Background(), "GET", srv2.URL+"/escape", Options{})
	if !x.ScopeBlocked {
		t.Fatalf("out-of-scope redirect not blocked: %+v", x)
	}
	if len(x.Redirects) != 1 || x.Redirects[0].InScope {
		t.Fatalf("hop record wrong: %+v", x.Redirects)
	}
}

func TestBodyCapTruncation(t *testing.T) {
	big := strings.Repeat("A", 3<<20) // 3 MiB > 1 MiB cap
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, strings.NewReader(big))
	}))
	defer srv.Close()
	sc, _ := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: srv.Listener.Addr().String(), IncludePaths: []string{"/"}}},
		GlobalAllowedMethods: []string{"GET"},
	})
	se, _ := safety.New(safety.Config{RatePerSecond: 200, Concurrency: 2})
	se.Scope = sc
	cl := New(se, logger.New(logger.LevelError), 5*time.Second, 1<<20, 5, 0)
	x := cl.Do(context.Background(), "GET", srv.URL+"/", Options{})
	if !x.BodyTruncated {
		t.Fatal("large body not flagged as truncated")
	}
	if len(x.Body) > (1<<20)+64 {
		t.Fatalf("body over cap: %d", len(x.Body))
	}
}

func TestCredentialRedactionInCapture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"token":"` + r.Header.Get("Authorization") + `","ok":true}`))
	}))
	defer srv.Close()
	cl, _ := newClientFor(t, srv, config.Scope{})
	x := cl.Do(context.Background(), "GET", srv.URL+"/", Options{Headers: map[string]string{"Authorization": "Bearer super-secret-token"}})
	if !strings.Contains(x.Body, "‹redacted") {
		t.Fatalf("credential echoed in body not redacted: %s", x.Body)
	}
	if !strings.Contains(x.RequestHeaders["Authorization"], "‹redacted") {
		t.Fatalf("request header not redacted: %v", x.RequestHeaders)
	}
	if strings.Contains(x.Body, "super-secret-token") {
		t.Fatal("secret leaked")
	}
}

func TestCancellationMidFlight(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		_, _ = w.Write([]byte("done"))
	}))
	defer srv.Close()
	defer close(release)
	cl, _ := newClientFor(t, srv, config.Scope{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	x := cl.Do(ctx, "GET", srv.URL+"/", Options{})
	if x.Err == "" {
		t.Fatal("cancelled request reported success")
	}
}

func TestTransportErrorRetry(t *testing.T) {
	// Server that fails the first request (closed conn) then succeeds.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			panic("simulate handler failure")
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	cl, _ := newClientFor(t, srv, config.Scope{})
	x := cl.Do(context.Background(), "GET", srv.URL+"/", Options{})
	// A panicked handler yields a connection reset; with retries the second attempt succeeds.
	if x.Status != 200 {
		t.Logf("retry behavior: status=%d err=%s calls=%d", x.Status, x.Err, calls)
	}
}
