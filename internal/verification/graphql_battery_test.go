package verification

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/graphql"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/mockapp"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// TestEngineGraphQLNodeBypass proves the §26 battery: a node lookup replayed
// as a non-owner against the vulnerable lab resolver confirms an
// object-level finding with the full control battery.
func TestEngineGraphQLNodeBypass(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	h := newGraphQLHarness(t, srv, newMemEvidenceStore(), nil)
	op, ok := graphql.Harvest(srv.URL+"/graphql",
		`{"query":"query($id:String!){node(id:$id){id owner title}}","variables":{"id":"doc-3001"}}`, "test")
	if !ok {
		t.Fatal("harvest failed")
	}
	item := TestItem{
		URL: srv.URL + "/graphql", Method: "POST", Resource: "document",
		Identifier: "doc-3001", Owner: "userA", OwnerState: ownership.StateDeclared,
		Category: finding.CatHorizontal, EndpointID: "graphql",
	}
	f := h.engine.VerifyGraphQL(context.Background(), op, item)
	if f.State != finding.StateConfirmed {
		t.Fatalf("GraphQL node bypass must CONFIRM: state=%s reason=%s", f.State, f.Reason)
	}
	if !strings.Contains(f.Title, "GraphQL") {
		t.Fatalf("transport not recorded in title: %s", f.Title)
	}
	for _, ctl := range []string{finding.ControlIdentitySeparation, finding.ControlOwnerBaseline,
		finding.ControlNegativeControl, finding.ControlNonOwnerAccess, finding.ControlRepeatability} {
		if f.ControlStatus(ctl) != finding.StatusPass {
			t.Fatalf("control %s not PASS: %v", ctl, f.Controls)
		}
	}
}

// newGraphQLHarness is newPolicyHarness with the write-method gate enabled:
// GraphQL over HTTP uses POST, which the read-only default safety policy
// blocks. Operators running the GraphQL battery must allow POST explicitly
// (scope + safety.allow_write_methods) — the same opt-in as write testing.
func newGraphQLHarness(t *testing.T, srv *httptest.Server, store evidence.Store, cfgMod func(*config.Verification)) *policyHarness {
	t.Helper()
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: srv.Listener.Addr().String(), IncludePaths: []string{"/"}}},
		GlobalAllowedMethods: []string{"GET", "POST"},
	})
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: 200, Concurrency: 4, MaxRetries: 0, WriteAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	log := logger.New(logger.LevelError)
	cl := httpclient.New(se, log, 3*time.Second, 1<<20, 5, 0)
	return &policyHarness{engine: &Engine{
		Client: cl, Auth: authForHarness(t, srv), Scope: sc, Evid: evidence.NewEngine(store), Store: noopFindingStore{},
		Cfg: cfgForHarness(cfgMod), Log: log, Session: "graphql-test",
	}}
}
