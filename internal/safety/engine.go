// Package safety enforces the testing safety rules in code: request budgets,
// per-host rate limiting, bounded concurrency, destructive-method guards and
// cancellation. Every HTTP request the tool makes flows through Engine:
// Reserve validates and throttles BEFORE send; Release returns the slot.
package safety

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// Sentinel errors callers can test against with errors.Is.
var (
	ErrOutOfScope       = errors.New("out of scope")
	ErrBudgetExhausted  = errors.New("request budget exhausted")
	ErrMethodNotAllowed = errors.New("method not allowed by safety policy")
	ErrCancelled        = errors.New("cancelled")
)

// Engine combines scope checking, budgets, rate limiting and method guards.
type Engine struct {
	Scope *scope.Checker

	writeAllowed     bool
	blockDestructive bool
	destructiveRe    []*regexp.Regexp
	maxRetries       int

	mu           sync.Mutex
	perHostNext  map[string]time.Time
	globalNext   time.Time
	minGlobalGap time.Duration
	minHostGap   time.Duration
	sem          chan struct{}
}

// Config for the safety engine.
type Config struct {
	RatePerSecond     float64
	PerHostRatePerSec float64
	Concurrency       int
	WriteAllowed      bool
	BlockDestructive  bool
	BlockedPatterns   []string
	MaxRetries        int
}

// New builds the engine. If cfg has no Scope attached via the Scope field,
// the engine MUST NOT be used for requests: Reserve refuses with a clear
// error rather than allowing unscoped traffic.
func New(cfg Config) (*Engine, error) {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 4
	}
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = 5
	}
	e := &Engine{
		writeAllowed:     cfg.WriteAllowed,
		blockDestructive: cfg.BlockDestructive,
		maxRetries:       cfg.MaxRetries,
		perHostNext:      map[string]time.Time{},
		sem:              make(chan struct{}, cfg.Concurrency),
		minGlobalGap:     time.Duration(float64(time.Second) / cfg.RatePerSecond),
	}
	if cfg.PerHostRatePerSec > 0 {
		e.minHostGap = time.Duration(float64(time.Second) / cfg.PerHostRatePerSec)
	}
	for _, p := range cfg.BlockedPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("blocked pattern %q: %w", p, err)
		}
		e.destructiveRe = append(e.destructiveRe, re)
	}
	return e, nil
}

// Reserve validates a request against scope + budgets + method policy, then
// blocks until the rate limit permits it. It acquires one concurrency slot;
// the caller MUST call Release when done (including on error paths).
func (e *Engine) Reserve(ctx context.Context, method, rawURL string) error {
	select {
	case <-ctx.Done():
		return ErrCancelled
	default:
	}
	if e.Scope == nil {
		return fmt.Errorf("%w: no scope checker configured (safety fail-safe)", ErrOutOfScope)
	}
	// Method policy first: destructive-method refusals must be reported as
	// such regardless of scope verdict.
	if err := e.checkMethod(method, rawURL); err != nil {
		return err
	}
	if d := e.Scope.Check(method, rawURL); !d.Allowed {
		return fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
	}
	if d := e.Scope.CountRequest(rawURL); !d.Allowed {
		return fmt.Errorf("%w: %s", ErrBudgetExhausted, d.Reason)
	}
	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		return ErrCancelled
	}
	// Rate limiting: compute this request's earliest send time. Holding the
	// mutex only to book the slot; actual waiting happens outside it.
	now := time.Now()
	e.mu.Lock()
	next := e.globalNext
	if now.After(next) {
		next = now
	}
	e.globalNext = next.Add(e.minGlobalGap)
	var hostGap time.Duration
	if u, err := url.Parse(rawURL); err == nil && e.minHostGap > 0 {
		host := u.Host
		hn, ok := e.perHostNext[host]
		if !ok || now.After(hn) {
			hn = now
		}
		e.perHostNext[host] = hn.Add(e.minHostGap)
		hostGap = hn.Add(e.minHostGap).Sub(now)
	}
	e.mu.Unlock()
	wait := next.Sub(now)
	if hostGap > wait {
		wait = hostGap
	}
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			e.Release()
			return ErrCancelled
		}
	}
	return nil
}

// Release returns the concurrency slot.
func (e *Engine) Release() {
	select {
	case <-e.sem:
	default:
	}
}

var writeMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

func (e *Engine) checkMethod(method, rawURL string) error {
	if !writeMethods[method] {
		return nil
	}
	if !e.writeAllowed {
		return fmt.Errorf("%w: %s (enable safety.allow_write_methods explicitly)", ErrMethodNotAllowed, method)
	}
	if e.blockDestructive {
		u, err := url.Parse(rawURL)
		if err == nil {
			for _, re := range e.destructiveRe {
				if re.MatchString(u.Path) {
					return fmt.Errorf("%w: destructive path %s matches %s", ErrMethodNotAllowed, u.Path, re.String())
				}
			}
		}
	}
	return nil
}

// MaxRetries returns the configured retry ceiling.
func (e *Engine) MaxRetries() int { return e.maxRetries }

// WriteAllowed reports whether write methods are enabled.
func (e *Engine) WriteAllowed() bool { return e.writeAllowed }

// Describe renders the safety posture for the pre-scan summary.
func (e *Engine) Describe() string {
	rps := 0.0
	if e.minGlobalGap > 0 {
		rps = float64(time.Second) / float64(e.minGlobalGap)
	}
	return fmt.Sprintf("rate=%.1f rps concurrency=%d write_methods=%v destructive_block=%v retries=%d",
		rps, cap(e.sem), e.writeAllowed, e.blockDestructive, e.maxRetries)
}
