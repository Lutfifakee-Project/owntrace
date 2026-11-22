package workflow

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/mockapp"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// TestExecutorAgainstMockApp runs the demo flow against the REAL bundled
// lab application (not the mini-lab), exposing any executor/mockapp drift.
func TestExecutorAgainstMockApp(t *testing.T) {
	app := mockapp.New()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	base := srv.URL

	cfg := &config.Config{}
	cfg.Auth.Profiles = []config.Profile{
		{Name: "alice", Type: "bearer", Token: app.Tokens()["alice"], Role: "user"},
		{Name: "bob", Type: "bearer", Token: app.Tokens()["bob"], Role: "user"},
	}
	am, err := auth.New(cfg, logger.New(logger.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: strings.TrimPrefix(base, "http://"), Schemes: []string{"http"}}},
		GlobalAllowedMethods: []string{"GET", "HEAD", "OPTIONS", "POST", "DELETE", "PUT", "PATCH"},
		MaxRequestsTotal:     500,
	})
	if err != nil {
		t.Fatal(err)
	}
	se, err := safety.New(safety.Config{RatePerSecond: 100, Concurrency: 2, WriteAllowed: true, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	se.Scope = sc
	cl := httpclient.New(se, logger.New(logger.LevelError), 0, 1<<20, 3, 1)
	x := &Executor{Client: cl, Auth: am, Scope: sc, Log: logger.New(logger.LevelError), Base: base}

	fl := demoFlow(t, base)
	res := x.Run(context.Background(), fl, "alice")
	if !res.OK {
		for _, st := range res.Steps {
			t.Logf("step %s %s -> status=%d ok=%v (%s)", st.Method, st.URL, st.Status, st.OK, st.Detail)
		}
		t.Fatalf("flow against mockapp failed: %s", res.Err)
	}
	if !strings.HasPrefix(res.State["doc_id"], "wfdoc-") {
		t.Fatalf("unexpected identifier: %q", res.State["doc_id"])
	}
}
