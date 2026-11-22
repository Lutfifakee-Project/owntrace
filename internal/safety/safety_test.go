package safety

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

func newEngine(t *testing.T, write bool) *Engine {
	t.Helper()
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: "api.test", IncludePaths: []string{"/"}, AllowedMethods: []string{"GET", "POST", "PUT"}}},
		GlobalAllowedMethods: []string{"GET", "POST", "PUT"},
		BlockedPathPatterns:  config.DefaultBlockedPatterns(),
		MaxRequestsTotal:     100,
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{RatePerSecond: 100, Concurrency: 2, WriteAllowed: write, BlockDestructive: true,
		BlockedPatterns: config.DefaultBlockedPatterns(), MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.Scope = sc
	return e
}

func TestMethodGuardBlocksWritesByDefault(t *testing.T) {
	e := newEngine(t, false)
	ctx := context.Background()
	err := e.Reserve(ctx, "POST", "http://api.test/api/things")
	e.Release()
	if !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("POST should be refused without opt-in, got: %v", err)
	}
	err = e.Reserve(ctx, "DELETE", "http://api.test/api/things/1")
	e.Release()
	if !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("DELETE should be refused, got: %v", err)
	}
}

func TestWriteOptInAllowsButDestructivePathsBlocked(t *testing.T) {
	e := newEngine(t, true)
	ctx := context.Background()
	if err := e.Reserve(ctx, "POST", "http://api.test/api/things"); err != nil {
		e.Release()
		t.Fatalf("POST with opt-in should pass: %v", err)
	}
	e.Release()
	err := e.Reserve(ctx, "PUT", "http://api.test/api/orders/1/delete")
	e.Release()
	if !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("destructive path should be blocked even with opt-in: %v", err)
	}
	err = e.Reserve(ctx, "PUT", "http://api.test/api/users/1/password")
	e.Release()
	if !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("password path should be blocked: %v", err)
	}
}

func TestOutOfScopeRefused(t *testing.T) {
	e := newEngine(t, false)
	err := e.Reserve(context.Background(), "GET", "http://other-host.example/x")
	e.Release()
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected out-of-scope, got: %v", err)
	}
}

func TestConcurrencyBound(t *testing.T) {
	e := newEngine(t, false)
	ctx := context.Background()
	done := make(chan struct{})
	// Acquire 2 slots (cap), then a third must block.
	for i := 0; i < 2; i++ {
		if err := e.Reserve(ctx, "GET", "http://api.test/x"); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	go func() {
		_ = e.Reserve(ctx, "GET", "http://api.test/x")
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("third reservation passed a 2-slot semaphore")
	case <-time.After(150 * time.Millisecond):
	}
	e.Release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("released slot did not unblock waiter")
	}
	e.Release()
	e.Release()
}

func TestBudgetExhaustion(t *testing.T) {
	e := newEngine(t, false)
	ctx := context.Background()
	// scope budget is 100 in fixture
	var err error
	for i := 0; i < 101; i++ {
		err = e.Reserve(ctx, "GET", "http://api.test/x")
		if err != nil {
			break
		}
		e.Release()
	}
	e.Release()
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("budget not enforced, last err: %v", err)
	}
}

func TestCancellation(t *testing.T) {
	e := newEngine(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := e.Reserve(ctx, "GET", "http://api.test/x")
	e.Release()
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancelled context should refuse: %v", err)
	}
}
