package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

const demoWorkflow = `
version: 1
flows:
  - name: doc-approval
    owner_profile: alice
    resource: workflow_doc
    policy: "approval restricted to approver/admin roles"
    steps:
      - name: csrf
        method: POST
        url: "{{base}}/api/v1/workflows/csrf"
        extract: {csrf: {from: json, path: "token"}}
      - name: create-doc
        method: POST
        url: "{{base}}/api/v1/workflows/docs"
        headers: {X-Flow-Token: "{{csrf}}"}
        body: '{"title":"owntrace-{{random}}"}'
        expect: {status: 201}
        extract: {doc_id: {from: json, path: "document.id"}}
      - name: approve-doc
        method: POST
        url: "{{base}}/api/v1/workflows/docs/{{doc_id}}/approve"
        headers: {X-Flow-Token: "{{csrf}}"}
        expect: {status: 200}
    negative_control:
      name: approve-nonexistent
      method: POST
      url: "{{base}}/api/v1/workflows/docs/ot-neg-{{random}}/approve"
      headers: {X-Flow-Token: "{{csrf}}"}
    cleanup:
      - name: delete-doc
        method: DELETE
        url: "{{base}}/api/v1/workflows/docs/{{doc_id}}"
        headers: {X-Flow-Token: "{{csrf}}"}
`

// lab is a minimal workflow laboratory implementing the same surface as the
// bundled mockapp workflow fixture (self-contained for executor tests).
type lab struct {
	mu      sync.Mutex
	seq     int
	csrf    map[string]bool
	docs    map[string]*labDoc
	decoy   bool // when true, approve succeeds even for nonexistent docs
	created []string
}

type labDoc struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Title string `json:"title"`
}

func (l *lab) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/workflows/csrf", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		l.seq++
		tok := fmt.Sprintf("csrf-%d", l.seq)
		l.csrf[tok] = true
		_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
	})
	mux.HandleFunc("/api/v1/workflows/docs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		if !l.csrf[r.Header.Get("X-Flow-Token")] {
			w.WriteHeader(403)
			return
		}
		owner := map[string]string{
			"tok-alice": "alice", "tok-bob": "bob",
		}[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		l.seq++
		doc := &labDoc{ID: fmt.Sprintf("wfdoc-%d", l.seq), Owner: owner, Title: "t"}
		l.docs[doc.ID] = doc
		l.created = append(l.created, doc.ID)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"document": doc})
	})
	mux.HandleFunc("/api/v1/workflows/docs/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/workflows/docs/")
		l.mu.Lock()
		defer l.mu.Unlock()
		switch {
		case rest == "" || strings.HasSuffix(rest, "/"):
			w.WriteHeader(404)
		case strings.HasSuffix(rest, "/approve") && r.Method == http.MethodPost:
			id := strings.TrimSuffix(rest, "/approve")
			if !l.csrf[r.Header.Get("X-Flow-Token")] {
				w.WriteHeader(403)
				return
			}
			if _, ok := l.docs[id]; !ok && !l.decoy {
				w.WriteHeader(404) // negative control denied
				return
			}
			if d := l.docs[id]; d != nil {
				d.Title = "approved:" + d.Title // state change observable
			}
			w.WriteHeader(200)
		case r.Method == http.MethodGet:
			d, ok := l.docs[rest]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"document": d})
		case r.Method == http.MethodDelete:
			d, ok := l.docs[rest]
			if !ok {
				w.WriteHeader(404)
				return
			}
			owner := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !(owner == "tok-alice" && d.Owner == "alice" || owner == "tok-bob" && d.Owner == "bob") {
				w.WriteHeader(403)
				return
			}
			delete(l.docs, rest)
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	})
	return mux
}

func newLab(t *testing.T, decoy bool) (base string, l *lab) {
	t.Helper()
	l = &lab{csrf: map[string]bool{}, docs: map[string]*labDoc{}, decoy: decoy}
	srv := httptest.NewServer(l.handler())
	t.Cleanup(srv.Close)
	return srv.URL, l
}

func testExecutor(t *testing.T, base string) *Executor {
	t.Helper()
	cfg := &config.Config{}
	cfg.Auth.Profiles = []config.Profile{
		{Name: "alice", Type: "bearer", Token: "tok-alice", Role: "user"},
		{Name: "bob", Type: "bearer", Token: "tok-bob", Role: "user"},
	}
	am, err := auth.New(cfg, logger.New(logger.LevelError))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := scope.New(config.Scope{
		Targets:              []config.ScopeTarget{{Host: strings.TrimPrefix(base, "http://"), Schemes: []string{"http"}}},
		GlobalAllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
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
	return &Executor{Client: cl, Auth: am, Scope: sc, Log: logger.New(logger.LevelError)}
}

// demoFlow instantiates the demo workflow against the lab base URL.
func demoFlow(t *testing.T, base string) *Flow {
	t.Helper()
	data := strings.ReplaceAll(demoWorkflow, "{{base}}", base)
	f, err := ParseFile([]byte(data))
	if err != nil {
		t.Fatalf("parse demo workflow: %v", err)
	}
	return &f.Flows[0]
}

// TestParseValidatesStructure proves fail-closed parser validation.
func TestParseValidatesStructure(t *testing.T) {
	if _, err := ParseFile([]byte("version: 1\nflows: []")); err == nil {
		t.Fatal("empty flows accepted")
	}
	if _, err := ParseFile([]byte("version: 1\nflows:\n  - name: x\n    steps:\n      - url: 'ftp://x'")); err == nil {
		t.Fatal("non-http URL accepted")
	}
	if _, err := ParseFile([]byte("version: 1\nflows:\n  - name: x\n    steps:\n      - url: 'http://x'\n        extract: {a: {from: javascript, path: x}}")); err == nil {
		t.Fatal("unknown extract source accepted")
	}
	if _, err := ParseFile([]byte(demoWorkflow)); err != nil {
		t.Fatalf("valid workflow rejected: %v", err)
	}
}

// TestExecutorRunsFlowWithState proves substitution, extraction, expectation
// checks, the negative control and success-path cleanup (§25).
func TestExecutorRunsFlowWithState(t *testing.T) {
	base, l := newLab(t, false)
	x := testExecutor(t, base)
	fl := demoFlow(t, base)

	res := x.Run(context.Background(), fl, "alice")
	if !res.OK {
		t.Fatalf("flow failed: %s\nsteps: %+v", res.Err, res.Steps)
	}
	if res.State["csrf"] == "" || res.State["doc_id"] == "" {
		t.Fatalf("extraction failed: %v", res.State)
	}
	if !res.NegControlDenied {
		t.Fatal("negative control not recorded as denied")
	}
	// Success-path cleanup ran: the created document is gone (owner delete).
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, still := l.docs[res.State["doc_id"]]; still {
		t.Fatal("cleanup did not delete the disposable document")
	}
}

// TestExecutorNegativeControlDecoyBlocksFlow proves fail-closed: when the
// application does NOT deny the negative control, the flow aborts (the
// surface is a decoy and can never support a business-flow verdict).
func TestExecutorNegativeControlDecoyBlocksFlow(t *testing.T) {
	base, _ := newLab(t, true) // lab approves even nonexistent docs
	x := testExecutor(t, base)
	fl := demoFlow(t, base)

	res := x.Run(context.Background(), fl, "alice")
	if res.OK {
		t.Fatal("decoy flow completed — negative control must abort the flow")
	}
	if !strings.Contains(res.Err, "negative control") {
		t.Fatalf("abort reason not actionable: %s", res.Err)
	}
}

// TestExecutorExpectationAbortsFlow proves preconditions are fail-closed.
func TestExecutorExpectationAbortsFlow(t *testing.T) {
	base, _ := newLab(t, false)
	x := testExecutor(t, base)
	fl := &Flow{
		Name: "strict", OwnerProfile: "alice",
		Steps: []Step{{
			Name: "expect-impossible", Method: "POST",
			URL:    base + "/api/v1/workflows/csrf",
			Expect: &Expect{Status: 418},
		}},
	}
	res := x.Run(context.Background(), fl, "alice")
	if res.OK || !strings.Contains(res.Err, "expected HTTP 418") {
		t.Fatalf("unmet expectation did not abort the flow: %+v", res)
	}
}

// TestExecutorScopeRefusal proves workflow steps respect deny-by-default
// scope: an out-of-scope step is refused, never sent.
func TestExecutorScopeRefusal(t *testing.T) {
	base, _ := newLab(t, false)
	x := testExecutor(t, base)
	fl := &Flow{
		Name: "escapist", OwnerProfile: "alice",
		Steps: []Step{{
			Name: "out-of-scope", Method: "GET",
			URL: "http://other-host.invalid/api",
		}},
	}
	res := x.Run(context.Background(), fl, "alice")
	if res.OK || !res.Denied || !strings.Contains(res.Err, "refused by scope") {
		t.Fatalf("out-of-scope step was not refused: %+v", res)
	}
}
