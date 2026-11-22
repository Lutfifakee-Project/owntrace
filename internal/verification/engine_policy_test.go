// §9.3 mandatory security regression tests: each invariant is exercised
// with its weakening configuration DISABLED, proving the invariant holds
// anyway. These tests run the real verification engine against the mock
// application (or a hostile stub server) — not against the policy in
// isolation.
package verification

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/mockapp"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// memEvidenceStore is an in-memory evidence.Store with hash-chain support.
type memEvidenceStore struct {
	mu      sync.Mutex
	records map[string]*evidence.Record
	heads   map[string]string
	seq     int
}

func newMemEvidenceStore() *memEvidenceStore {
	return &memEvidenceStore{records: map[string]*evidence.Record{}, heads: map[string]string{}}
}

func (m *memEvidenceStore) SaveEvidence(r *evidence.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[r.ID] = r
	if r.SessionID != "" {
		m.heads[r.SessionID] = r.SHA256
	}
	return nil
}

func (m *memEvidenceStore) GetEvidence(findingID string) ([]*evidence.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*evidence.Record
	for _, r := range m.records {
		if r.FindingID == findingID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memEvidenceStore) NextEvidenceSeq() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	return m.seq
}

func (m *memEvidenceStore) LastEvidenceHash(sessionID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.heads[sessionID], nil
}

// failingEvidenceStore persists nothing: every capture fails.
type failingEvidenceStore struct{}

func (failingEvidenceStore) SaveEvidence(*evidence.Record) error {
	return errors.New("simulated storage outage")
}
func (failingEvidenceStore) GetEvidence(string) ([]*evidence.Record, error) { return nil, nil }
func (failingEvidenceStore) NextEvidenceSeq() int                           { return 0 }
func (failingEvidenceStore) LastEvidenceHash(string) (string, error)        { return "", nil }

// policyHarness wires a real engine against a test server.
type policyHarness struct {
	engine *Engine
}

func newPolicyHarness(t *testing.T, srv *httptest.Server, store evidence.Store, cfgMod func(*config.Verification)) *policyHarness {
	t.Helper()
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: srv.Listener.Addr().String(), IncludePaths: []string{"/"}}},
		GlobalAllowedMethods: []string{"GET", "POST"},
	})
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: 200, Concurrency: 4, MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	log := logger.New(logger.LevelError)
	cl := httpclient.New(se, log, 3*time.Second, 1<<20, 5, 0)
	return &policyHarness{engine: &Engine{
		Client: cl, Auth: authForHarness(t, srv), Scope: sc, Evid: evidence.NewEngine(store), Store: noopFindingStore{},
		Cfg: cfgForHarness(cfgMod), Log: log, Session: "policy-test",
	}}
}

func cfgForHarness(mod func(*config.Verification)) config.Verification {
	cfg := config.Verification{Repeats: 1, CacheBust: true, AnonymousTest: true,
		MinOwnerStateForConfirmed: "declared"}
	if mod != nil {
		mod(&cfg)
	}
	return cfg
}

// authForHarness builds profiles using the mockapp fixture tokens so every
// mockapp-based policy test works unmodified.
func authForHarness(t *testing.T, srv *httptest.Server) *auth.Manager {
	t.Helper()
	cfg := &config.Config{}
	cfg.Auth.Profiles = []config.Profile{
		{Name: "userA", Type: "bearer", Token: "tok-alice-fixed-lab-token", Role: "user",
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/api/v1/profile", Method: "GET", Field: "user.id"}},
		{Name: "userB", Type: "bearer", Token: "tok-bob-fixed-lab-token", Role: "user",
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/api/v1/profile", Method: "GET", Field: "user.id"}},
		{Name: "root", Type: "bearer", Token: "tok-admin-fixed-lab-token", Role: "admin",
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/api/v1/profile", Method: "GET", Field: "user.id"}},
	}
	m, err := auth.New(cfg, logger.New(logger.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type noopFindingStore struct{}

func (noopFindingStore) SaveFinding(*finding.Finding) error { return nil }

// Sec-9.3-1: Same-identity profiles cannot produce CONFIRMED — even with
// require_identity_separation explicitly DISABLED.
func TestSecSameIdentityCannotConfirmEvenWhenConfigDisabled(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), func(c *config.Verification) {
		c.RequireIdentitySeparation = false // weakened on purpose
	})
	// Replace the auth manager: BOTH profiles carry userA's token.
	cfg := &config.Config{}
	cfg.Auth.Profiles = []config.Profile{
		{Name: "userA", Type: "bearer", Token: app.Tokens()["alice"], Role: "user",
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/api/v1/profile", Method: "GET", Field: "user.id"}},
		{Name: "userB", Type: "bearer", Token: app.Tokens()["alice"], Role: "user", // SAME identity
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/api/v1/profile", Method: "GET", Field: "user.id"}},
	}
	m, err := auth.New(cfg, logger.New(logger.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	h.engine.Auth = m

	item := TestItem{
		URL: srv.URL + "/api/v1/orders/o-1001", Method: "GET", Resource: "order",
		Identifier: "o-1001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.State == finding.StateConfirmed {
		t.Fatalf("SECURITY REGRESSION: same-identity profiles produced CONFIRMED (reason: %s)", f.Reason)
	}
	if !strings.Contains(f.Reason, "SAME identity") {
		t.Fatalf("expected same-identity explanation, got: %s", f.Reason)
	}
}

// Sec-9.3-2: A negative control that cannot execute blocks CONFIRMED.
func TestSecMissingNegativeControlCannotConfirm(t *testing.T) {
	mutated := mutatedIdentifier("o-1001")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/profile", func(w http.ResponseWriter, r *http.Request) {
		id := map[string]string{
			"Bearer tok-alice-fixed-lab-token": "usr-alice",
			"Bearer tok-bob-fixed-lab-token":   "usr-bob",
		}[r.Header.Get("Authorization")]
		if id == "" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"user":{"id":"` + id + `"}}`))
	})
	mux.HandleFunc("/api/v1/orders/o-1001", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"order":{"id":"o-1001","owner":"alice","item":"widget","total":100}}`))
	})
	// The mutated (nonexistent-object) URL kills the connection: the control
	// cannot execute at all.
	mux.HandleFunc("/api/v1/orders/"+mutated, func(w http.ResponseWriter, r *http.Request) {
		panic("connection reset")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	item := TestItem{
		URL: srv.URL + "/api/v1/orders/o-1001", Method: "GET", Resource: "order",
		Identifier: "o-1001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.State == finding.StateConfirmed {
		t.Fatalf("SECURITY REGRESSION: CONFIRMED without an executable negative control (reason: %s)", f.Reason)
	}
	if f.ControlStatus(finding.ControlNegativeControl) == finding.StatusPass {
		t.Fatal("negative control recorded as PASS despite execution failure")
	}
}

// Sec-9.3-3: Evidence persistence failure blocks CONFIRMED.
func TestSecEvidencePersistenceFailureCannotConfirm(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, failingEvidenceStore{}, nil)
	item := TestItem{
		URL: srv.URL + "/api/v1/orders/o-1001", Method: "GET", Resource: "order",
		Identifier: "o-1001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.State == finding.StateConfirmed {
		t.Fatalf("SECURITY REGRESSION: CONFIRMED with failed evidence persistence (reason: %s)", f.Reason)
	}
	if !strings.Contains(f.Reason, "evidence") {
		t.Fatalf("expected evidence-loss explanation, got: %s", f.Reason)
	}
}

// Sec-9.3-4: With cache analysis disabled by configuration, the invariant
// still holds — no CONFIRMED without cache-artifact ruling.
func TestSecCacheAnalysisDisabledStillBlocksConfirmation(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), func(c *config.Verification) {
		c.CacheBust = false // weakened on purpose
	})
	item := TestItem{
		URL: srv.URL + "/api/v1/orders/o-1001", Method: "GET", Resource: "order",
		Identifier: "o-1001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.State == finding.StateConfirmed {
		t.Fatalf("SECURITY REGRESSION: CONFIRMED without cache analysis (reason: %s)", f.Reason)
	}
	if !strings.Contains(f.Reason, "cache analysis") {
		t.Fatalf("expected cache-analysis explanation, got: %s", f.Reason)
	}
}

// Sec-9.3-5: A cache that IGNORES cache busters cannot be ruled out — no
// CONFIRMED (SUSPECTED with cache explanation).
func TestSecCacheIgnoringBustersCannotConfirm(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	// Warm the path-keyed cache as the owner.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/pathcache/doc-3001", nil)
	req.Header.Set("Authorization", "Bearer "+app.Tokens()["alice"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	item := TestItem{
		URL: srv.URL + "/api/v1/pathcache/doc-3001", Method: "GET", Resource: "document",
		Identifier: "doc-3001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.State == finding.StateConfirmed {
		t.Fatalf("SECURITY REGRESSION: CONFIRMED although the cache ignored the buster (reason: %s)", f.Reason)
	}
	if f.ControlStatus(finding.ControlCacheAnalysis) != finding.StatusFail {
		t.Fatalf("cache control must FAIL when the buster is ignored: %+v", f.Controls)
	}
}

// Sec-9.3-6: A generic 200 page for a nonexistent object (soft-404) yields
// INCONCLUSIVE — the owner baseline cannot contain the identifier.
func TestSecSoft404IsInconclusive(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	item := TestItem{
		URL: srv.URL + "/api/v1/soft404/o-1001", Method: "GET", Resource: "page",
		Identifier: "o-1001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.State != finding.StateInconclusive {
		t.Fatalf("soft-404 must be INCONCLUSIVE, got %s (reason: %s)", f.State, f.Reason)
	}
}

// Sec-9.3-7: A public admin-looking page must NOT confirm a vertical bypass.
func TestSecPublicAdminPageRejected(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	ep := &endpoints.Endpoint{ID: "ep-public-info", Method: "GET", Path: "/api/v1/admin/public-info", Adminish: true}
	f := h.engine.VerifyVertical(context.Background(), srv.URL+"/api/v1/admin/public-info", "GET", ep)
	if f == nil {
		t.Fatal("no finding produced")
	}
	if f.State == finding.StateConfirmed {
		t.Fatalf("SECURITY REGRESSION: public admin page confirmed as vertical bypass (reason: %s)", f.Reason)
	}
	if f.State != finding.StateRejected {
		t.Fatalf("public admin page must be REJECTED, got %s (reason: %s)", f.State, f.Reason)
	}
}

// Sec-9.3-8: The genuine vertical bypass (admin stats visible to non-admin,
// refused to anonymous) still confirms through the full policy.
func TestSecGenuineVerticalBypassStillConfirms(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	ep := &endpoints.Endpoint{ID: "ep-admin-stats", Method: "GET", Path: "/api/v1/admin/stats", Adminish: true}
	f := h.engine.VerifyVertical(context.Background(), srv.URL+"/api/v1/admin/stats", "GET", ep)
	if f == nil {
		t.Fatal("no finding produced")
	}
	if f.State != finding.StateConfirmed {
		t.Fatalf("genuine vertical bypass must confirm through the policy, got %s (reason: %s)", f.State, f.Reason)
	}
	for _, c := range []string{finding.ControlNegativeControl, finding.ControlPublicContent, finding.ControlCacheAnalysis, finding.ControlRepeatability} {
		if f.ControlStatus(c) != finding.StatusPass {
			t.Fatalf("control %s not PASS on a genuine confirmation: %+v", c, f.Controls)
		}
	}
}

// Sec-9.3-9: The genuine horizontal IDOR still confirms through the full
// policy (fixing the gate must not have broken true positives).
func TestSecGenuineHorizontalIDORStillConfirms(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	item := TestItem{
		URL: srv.URL + "/api/v1/orders/o-1001", Method: "GET", Resource: "order",
		Identifier: "o-1001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.State != finding.StateConfirmed {
		t.Fatalf("genuine horizontal IDOR must confirm through the policy, got %s (reason: %s)", f.State, f.Reason)
	}
}

// Sec-9.3-10: An anonymous request that reflects the identifier but serves
// no object data (echo decoy) cannot confirm the anonymous category.
func TestSecAnonymousEchoDecoyRejected(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	item := TestItem{
		URL: srv.URL + "/api/v1/echo/o-1001", Method: "GET", Resource: "decoy",
		Identifier: "o-1001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyAnonymous(context.Background(), item)
	if f.State == finding.StateConfirmed {
		t.Fatalf("SECURITY REGRESSION: anonymous echo decoy confirmed (reason: %s)", f.Reason)
	}
}

// Sec-9.3-11: An expired/invalid owner token yields INCONCLUSIVE — never a
// false REJECTED or CONFIRMED (authentication lifecycle handling, v0.3.0).
func TestSecExpiredOwnerTokenIsInconclusive(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	// Override owner profile with an invalid token.
	cfg := &config.Config{}
	cfg.Auth.Profiles = []config.Profile{
		{Name: "userA", Type: "bearer", Token: "tok-expired-invalid", Role: "user",
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/api/v1/profile", Method: "GET", Field: "user.id"}},
		{Name: "userB", Type: "bearer", Token: app.Tokens()["bob"], Role: "user",
			Identity: config.IdentityProbe{Endpoint: srv.URL + "/api/v1/profile", Method: "GET", Field: "user.id"}},
	}
	m, err := auth.New(cfg, logger.New(logger.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	h.engine.Auth = m

	item := TestItem{
		URL: srv.URL + "/api/v1/orders/o-1001", Method: "GET", Resource: "order",
		Identifier: "o-1001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal,
	}
	f := h.engine.VerifyItem(context.Background(), item)
	if f.State != finding.StateInconclusive {
		t.Fatalf("expired owner token must yield INCONCLUSIVE, got %s (reason: %s)", f.State, f.Reason)
	}
}

// v0.6.0 role matrix: the same privileged endpoint is tested per non-admin
// profile; both roles' findings are independent and complete.
func TestRoleMatrixCoversEveryNonAdminProfile(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	ep := &endpoints.Endpoint{ID: "ep-admin-stats", Method: "GET", Path: "/api/v1/admin/stats", Adminish: true}
	url := srv.URL + "/api/v1/admin/stats"

	results := map[string]finding.State{}
	for _, attacker := range []string{"userA", "userB"} {
		f := h.engine.VerifyVerticalPair(context.Background(), url, "GET", ep, "root", attacker)
		if f == nil {
			t.Fatalf("no finding for attacker %s", attacker)
		}
		results[attacker] = f.State
		if f.Requester != attacker {
			t.Fatalf("requester attribution wrong: %s", f.Requester)
		}
	}
	if results["userA"] != finding.StateConfirmed || results["userB"] != finding.StateConfirmed {
		t.Fatalf("role matrix incomplete: %+v", results)
	}
}

// Authorization consistency: identical admin content must be rejected when
// the endpoint is public — per role, in the matrix.
func TestRoleMatrixRejectsPublicSurfacePerRole(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newPolicyHarness(t, srv, newMemEvidenceStore(), nil)
	ep := &endpoints.Endpoint{ID: "ep-public", Method: "GET", Path: "/api/v1/admin/public-info", Adminish: true}
	url := srv.URL + "/api/v1/admin/public-info"

	for _, attacker := range []string{"userA", "userB"} {
		f := h.engine.VerifyVerticalPair(context.Background(), url, "GET", ep, "root", attacker)
		if f == nil || f.State != finding.StateRejected {
			t.Fatalf("public surface must be REJECTED for %s, got %+v", attacker, f)
		}
	}
}
