// Direct tests for the ownership mapper: declared mappings, controlled
// creation workflows and listing-membership inference (v0.3.0 focus:
// "OWNTRACE must know why it believes an object belongs to an owner").
package ownership_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/mockapp"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// scopeAllow implements the mapper's ScopeChecker against a real checker.
type scopeAllow struct{ c *scope.Checker }

func (s scopeAllow) Check(method, raw string) ownership.Decision {
	d := s.c.Check(method, raw)
	return ownership.Decision{Allowed: d.Allowed, Reason: d.Reason}
}

func newMapperHarness(t *testing.T, app *mockapp.App, srv *httptest.Server, cfgMod func(*config.Config)) *ownership.Mapper {
	t.Helper()
	cfg := &config.Config{}
	cfg.Auth.Profiles = []config.Profile{
		{Name: "userA", Type: "bearer", Token: app.Tokens()["alice"], Role: "user"},
		{Name: "userB", Type: "bearer", Token: app.Tokens()["bob"], Role: "user"},
	}
	if cfgMod != nil {
		cfgMod(cfg)
	}
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: srv.Listener.Addr().String(), IncludePaths: []string{"/"}, AllowedMethods: []string{"GET", "POST"}}},
		GlobalAllowedMethods: []string{"GET", "POST"},
	})
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: 100, Concurrency: 2, WriteAllowed: true, MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	am, err := auth.New(cfg, logger.New(logger.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	log := logger.New(logger.LevelError)
	return &ownership.Mapper{
		Cfg:    cfg,
		Client: httpclient.New(se, log, 3_000_000_000, 1<<20, 5, 0),
		Auth:   am,
		Evid:   evidence.NewEngine(&memStore{}),
		Log:    log,
		Scope:  scopeAllow{sc},
	}
}

type memStore struct {
	heads map[string]string
}

func (m *memStore) SaveEvidence(r *evidence.Record) error {
	if m.heads == nil {
		m.heads = map[string]string{}
	}
	if r.SessionID != "" {
		m.heads[r.SessionID] = r.SHA256
	}
	return nil
}
func (m *memStore) GetEvidence(string) ([]*evidence.Record, error) { return nil, nil }
func (m *memStore) NextEvidenceSeq() int                           { return 1 }
func (m *memStore) LastEvidenceHash(s string) (string, error)      { return m.heads[s], nil }

func TestMapperDeclaredObjects(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	base := srv.URL

	m := newMapperHarness(t, app, srv, func(c *config.Config) {
		c.Objects.Declared = []config.DeclaredObject{
			{Profile: "userA", Resource: "order", URL: base + "/api/v1/orders/o-1001", Identifiers: []string{"o-1001"}},
			{Profile: "userB", Resource: "order", URL: base + "/api/v1/orders/o-1004", Identifiers: []string{"o-1004"}},
		}
	})
	reg, notes := m.Build(context.Background(), "S-decl")
	if len(reg.List()) != 2 {
		t.Fatalf("declared objects: %d", len(reg.List()))
	}
	rec, ok := reg.Lookup("order", "o-1001", "")
	if !ok {
		t.Fatal("o-1001 record missing")
	}
	if rec.State != ownership.StateDeclared || rec.OwnerProfile != "userA" {
		t.Fatalf("declared mapping wrong: %+v", rec)
	}
	if len(rec.Provenance) == 0 {
		t.Fatal("declared ownership must carry explicit provenance (§4.2)")
	}
	if len(notes) == 0 {
		t.Fatal("notes must explain the mapping")
	}
}

func TestMapperCreationWorkflowConfirmsOwnership(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	base := srv.URL

	m := newMapperHarness(t, app, srv, func(c *config.Config) {
		c.Safety.AllowWriteMethods = true
		c.Objects.Creation = config.CreationWorkflow{
			Enabled:         true,
			Endpoint:        base + "/api/v1/orders",
			Method:          "POST",
			BodyTemplate:    `{"item":"owntrace-probe"}`,
			ContentType:     "application/json",
			ExtractField:    "order.id",
			ItemURLTemplate: base + "/api/v1/orders/{{id}}",
			Profiles:        []string{"userA", "userB"},
		}
	})
	reg, notes := m.Build(context.Background(), "S-create")
	if len(reg.List()) != 2 {
		t.Fatalf("created objects: %d", len(reg.List()))
	}
	for _, rec := range reg.List() {
		if rec.State != ownership.StateConfirmed {
			t.Fatalf("created object must be CONFIRMED ownership, got %s", rec.State)
		}
		if rec.OwnerProfile != "userA" && rec.OwnerProfile != "userB" {
			t.Fatalf("owner wrong: %+v", rec)
		}
	}
	if len(notes) == 0 {
		t.Fatal("notes must report creation")
	}
}

func TestMapperCreationRequiresScope(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	m := newMapperHarness(t, app, srv, func(c *config.Config) {
		c.Safety.AllowWriteMethods = true
		// Creation endpoint points OUTSIDE the declared target → must fail closed.
		c.Objects.Creation = config.CreationWorkflow{
			Enabled: true, Endpoint: "http://other-host.invalid/api/orders",
			Method: "POST", BodyTemplate: `{}`, ExtractField: "id",
			Profiles: []string{"userA"},
		}
	})
	_, notes := m.Build(context.Background(), "S-scope")
	joined := ""
	for _, n := range notes {
		joined += n + "\n"
	}
	if !contains(joined, "out of scope") {
		t.Fatalf("out-of-scope creation must be refused: %s", joined)
	}
}

func TestMapperMineCollectionInfersOwnership(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	base := srv.URL

	m := newMapperHarness(t, app, srv, func(c *config.Config) {
		c.Objects.MineCollections = []config.Collection{
			{Profile: "userA", URL: base + "/api/v1/orders", Resource: "order", IDFields: []string{"id"}},
			{Profile: "userB", URL: base + "/api/v1/orders", Resource: "order", IDFields: []string{"id"}},
		}
	})
	reg, notes := m.Build(context.Background(), "S-mine")
	for _, n := range notes {
		t.Logf("note: %s", n)
	}
	aRecords := 0
	bRecords := 0
	for _, rec := range reg.List() {
		if rec.OwnerProfile == "userA" && rec.Resource == "order" {
			aRecords++
		}
		if rec.OwnerProfile == "userB" && rec.Resource == "order" {
			bRecords++
		}
		if rec.State != ownership.StateInferred {
			t.Fatalf("listing membership must be INFERRED, got %s", rec.State)
		}
	}
	if aRecords == 0 || bRecords == 0 {
		t.Fatalf("inference incomplete: a=%d b=%d", aRecords, bRecords)
	}
	if len(notes) == 0 {
		t.Fatal("notes must report mining")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
