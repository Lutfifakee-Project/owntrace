package httpclient_test

import (
	"context"
	"net"

	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

func newGuardClient(t *testing.T, srv *httptest.Server, lookup httpclient.LookupFunc) *httpclient.Client {
	t.Helper()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: "rebind.test:" + strconv.Itoa(port), IncludePaths: []string{"/"}}},
		GlobalAllowedMethods: []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: 100, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	return httpclient.New(se, logger.New(logger.LevelError), 3*time.Second, 1<<20, 5, 0).WithLookup(lookup)
}

// v0.5.0: a hostname that resolves to a link-local/metadata address is
// refused even when the HOST itself is inside the operator's scope —
// DNS rebinding toward cloud metadata endpoints is impossible.
func TestDialGuardBlocksMetadataResolution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cl := newGuardClient(t, srv, func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "rebind.test" {
			// Attacker-controlled DNS: rebind toward the metadata endpoint.
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if lerr != nil {
			return nil, lerr
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, nil
	})
	// The httptest server listens on 127.0.0.1; the guard must refuse BEFORE
	// any connection is attempted.
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	x := cl.Do(context.Background(), "GET", "http://rebind.test:"+strconv.Itoa(port)+"/data", httpclient.Options{})
	if x.Err == "" {
		t.Fatal("metadata-rebinding resolution was dialed")
	}
	if !strings.Contains(x.Err, "forbidden") {
		t.Fatalf("unexpected refusal reason: %s", x.Err)
	}
}

// A permitted resolution reaches the authorized target.
func TestDialGuardAllowsPermittedResolution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	cl := newGuardClient(t, srv, func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "rebind.test" {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if lerr != nil {
			return nil, lerr
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, nil
	})
	x := cl.Do(context.Background(), "GET", "http://rebind.test:"+strconv.Itoa(port)+"/data", httpclient.Options{})
	if x.Err != "" || x.Status != 200 {
		t.Fatalf("permitted resolution blocked: %s", x.Err)
	}
}

// IP-literal metadata addresses are refused even as the direct target.
func TestDialGuardBlocksIPLiteralMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }))
	defer srv.Close()

	// Scope configured for the metadata IP itself (misconfiguration) — the
	// guard still refuses: link-local metadata is never contacted.
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: "169.254.169.254", IncludePaths: []string{"/"}}},
		GlobalAllowedMethods: []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}
	se, _ := safety.New(safety.Config{RatePerSecond: 100, Concurrency: 2})
	se.Scope = sc
	cl := httpclient.New(se, logger.New(logger.LevelError), 3*time.Second, 1<<20, 5, 0)
	x := cl.Do(context.Background(), "GET", "http://169.254.169.254/latest/meta-data/", httpclient.Options{})
	if x.Err == "" || !strings.Contains(x.Err, "forbidden") {
		t.Fatalf("IP-literal metadata target not refused: %+v", x)
	}
}
