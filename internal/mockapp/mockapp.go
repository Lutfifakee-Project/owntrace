// Package mockapp provides a deterministic, deliberately vulnerable test
// application used by OWNTRACE's integration tests and manual laboratory
// workflows (cmd/mockapp). It contains BOTH correctly protected objects and
// intentionally vulnerable endpoints so detection quality can be measured:
//
//	Vulnerable:   /api/v1/orders/{id}                (horizontal IDOR)
//	              /api/v1/documents/{id}             (auth'd IDOR, anon blocked)
//	              /api/v1/receipts/{id}              (fully anonymous)
//	              /api/v1/admin/stats                (vertical bypass)
//	              /api/v1/tenants/{tid}/files/{fid}  (cross-tenant)
//	              /api/v1/orders/{id}/notes          (nested, vulnerable)
//	Protected:    /api/v1/invoices/{id}              (owner-only, generic 404)
//	              /api/v1/invoices/{id}/payments     (nested, enforced)
//	              /api/v1/admin/users/{id}           (admin-only, 403)
//	              /api/v1/workspaces/{ws}/reports/{r}(nested + tenant enforced)
//	False-positive traps:
//	              /api/v1/echo/{id}        200 + echoes id, no object data
//	              /api/v1/cached-docs/{id} cache serves owner body to others
//	              /redirect/external       out-of-scope redirect (must be blocked)
//
// It is a TEST FIXTURE: never point it at production infrastructure, never
// deploy it publicly.
package mockapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// User is a mock application user.
type User struct {
	ID       string
	Username string
	Password string
	Role     string // "user" or "admin"
	Tenant   string
	Token    string
}

// App is the in-memory mock server.
type App struct {
	mu        sync.RWMutex
	users     []*User
	byUser    map[string]*User // username -> user
	byToken   map[string]*User // token -> user
	orders    map[string]*order
	invoices  map[string]*invoice
	documents map[string]*document
	receipts  map[string]*receipt
	files     map[string]*file
	notes     map[string][]note // by order id
	reports   map[string]*report
	cache     map[string]string // cached-docs path -> owner body
	orderSeq  int
	wfSeq     int
	wfDocs    map[string]*wfDoc
	wfCSRF    map[string]string // csrf token -> username
}

// wfDoc is a workflow-created document with a lifecycle state.
type wfDoc struct {
	ID     string `json:"id"`
	Owner  string `json:"owner"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

type order struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Item  string `json:"item"`
	Total int    `json:"total"`
}
type invoice struct {
	ID     string `json:"id"`
	Owner  string `json:"owner"`
	Number string `json:"number"`
	Amount int    `json:"amount"`
}
type document struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Title string `json:"title"`
}
type receipt struct {
	ID       string `json:"id"`
	Owner    string `json:"owner"`
	Merchant string `json:"merchant"`
}
type file struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
}
type note struct {
	ID     string `json:"id"`
	Author string `json:"author"`
	Text   string `json:"text"`
}
type report struct {
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	Title     string `json:"title"`
}

// New builds the app with fixed users and data.
func New() *App {
	a := &App{
		byUser:  map[string]*User{},
		byToken: map[string]*User{},
		orders:  map[string]*order{}, invoices: map[string]*invoice{},
		documents: map[string]*document{}, receipts: map[string]*receipt{},
		files: map[string]*file{}, notes: map[string][]note{},
		reports: map[string]*report{}, cache: map[string]string{},
		wfDocs: map[string]*wfDoc{}, wfCSRF: map[string]string{},
	}
	users := []*User{
		{ID: "usr-alice", Username: "alice", Password: "pw-alice", Role: "user", Tenant: "t-acme", Token: "tok-alice-fixed-lab-token"},
		{ID: "usr-bob", Username: "bob", Password: "pw-bob", Role: "user", Tenant: "t-globex", Token: "tok-bob-fixed-lab-token"},
		{ID: "usr-admin", Username: "admin", Password: "pw-admin", Role: "admin", Tenant: "t-acme", Token: "tok-admin-fixed-lab-token"},
	}
	for _, u := range users {
		a.users = append(a.users, u)
		a.byUser[u.Username] = u
		a.byToken[u.Token] = u
	}
	for i, id := range []string{"o-1001", "o-1002", "o-1003"} {
		a.orders[id] = &order{ID: id, Owner: "alice", Item: fmt.Sprintf("widget-%d", i+1), Total: 100 + i}
	}
	for i, id := range []string{"o-1004", "o-1005", "o-1006"} {
		a.orders[id] = &order{ID: id, Owner: "bob", Item: fmt.Sprintf("gadget-%d", i+1), Total: 200 + i}
	}
	a.orders["o-1007"] = &order{ID: "o-1007", Owner: "alice", Item: "widget-x", Total: 999}
	for _, id := range []string{"inv-2001", "inv-2002", "inv-2003"} {
		a.invoices[id] = &invoice{ID: id, Owner: "alice", Number: "INV-" + strings.TrimPrefix(id, "inv-"), Amount: 250}
	}
	for _, id := range []string{"inv-2004", "inv-2005"} {
		a.invoices[id] = &invoice{ID: id, Owner: "bob", Number: "INV-" + strings.TrimPrefix(id, "inv-"), Amount: 480}
	}
	a.documents["doc-3001"] = &document{ID: "doc-3001", Owner: "alice", Title: "Alice private doc"}
	a.documents["doc-3002"] = &document{ID: "doc-3002", Owner: "bob", Title: "Bob private doc"}
	a.receipts["r-6001"] = &receipt{ID: "r-6001", Owner: "alice", Merchant: "Coffee Shop"}
	a.receipts["r-6002"] = &receipt{ID: "r-6002", Owner: "bob", Merchant: "Book Store"}
	a.files["f-9001"] = &file{ID: "f-9001", Tenant: "t-acme", Name: "acme-q3.pdf"}
	a.files["f-9002"] = &file{ID: "f-9002", Tenant: "t-globex", Name: "globex-q3.pdf"}
	a.notes["o-1001"] = []note{{ID: "n-7001", Author: "alice", Text: "ship ASAP"}}
	a.notes["o-1004"] = []note{{ID: "n-7002", Author: "bob", Text: "gift wrap"}}
	a.reports["r-5001"] = &report{ID: "r-5001", Workspace: "ws-1", Title: "Alice ws report"}
	a.reports["r-5002"] = &report{ID: "r-5002", Workspace: "ws-2", Title: "Bob ws report"}
	return a
}

// Handler returns the HTTP handler.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/login", a.handleLogin)
	mux.HandleFunc("/api/v1/profile", a.requireAuth(a.handleProfile))
	mux.HandleFunc("/api/v1/orders", a.requireAuth(a.handleOrdersList))
	mux.HandleFunc("/api/v1/orders/", a.requireAuth(a.handleOrders))
	mux.HandleFunc("/api/v1/invoices/", a.requireAuth(a.handleInvoices))
	mux.HandleFunc("/api/v1/documents/", a.requireAuth(a.handleDocuments))
	mux.HandleFunc("/api/v1/cached-docs/", a.handleCachedDocs)
	mux.HandleFunc("/api/v1/receipts/", a.handleReceipts)
	mux.HandleFunc("/api/v1/admin/stats", a.requireAuth(a.handleAdminStats))
	mux.HandleFunc("/api/v1/admin/users/", a.requireAuth(a.handleAdminUsers))
	mux.HandleFunc("/api/v1/tenants/", a.requireAuth(a.handleTenantFiles))
	mux.HandleFunc("/api/v1/workspaces/", a.requireAuth(a.handleWorkspaces))
	mux.HandleFunc("/api/v1/echo/", a.handleEcho)
	mux.HandleFunc("/api/v1/soft404/", a.handleSoft404)
	mux.HandleFunc("/api/v1/pathcache/", a.handlePathCache)
	mux.HandleFunc("/api/v1/admin/public-info", a.handleAdminPublicInfo)
	mux.HandleFunc("/graphql", a.requireAuth(a.handleGraphQL))
	mux.HandleFunc("/api/v1/workflows/csrf", a.requireAuth(a.handleWorkflowCSRF))
	mux.HandleFunc("/api/v1/workflows/docs", a.requireAuth(a.handleWorkflowDocs))
	mux.HandleFunc("/api/v1/workflows/docs/", a.requireAuth(a.handleWorkflowDocs))
	mux.HandleFunc("/redirect/", a.handleRedirect)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]any{"error": "not found"})
	})
	return mux
}

// Tokens exposes fixed tokens for test setup.
func (a *App) Tokens() map[string]string {
	out := map[string]string{}
	for _, u := range a.users {
		out[u.Username] = u.Token
	}
	return out
}

// ResetCache clears the simulated response cache (between tests).
func (a *App) ResetCache() {
	a.mu.Lock()
	a.cache = map[string]string{}
	a.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) { writeJSON(w, 404, map[string]any{"error": "not found"}) }

func (a *App) userFrom(r *http.Request) *User {
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(authz, "Bearer ") {
		a.mu.RLock()
		defer a.mu.RUnlock()
		return a.byToken[strings.TrimPrefix(authz, "Bearer ")]
	}
	return nil
}

func (a *App) requireAuth(next func(http.ResponseWriter, *http.Request, *User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := a.userFrom(r)
		if u == nil {
			writeJSON(w, 401, map[string]any{"error": "authentication required"})
			return
		}
		next(w, r, u)
	}
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		notFound(w)
		return
	}
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	a.mu.RLock()
	u := a.byUser[req.Username]
	a.mu.RUnlock()
	if u == nil || u.Password != req.Password {
		writeJSON(w, 401, map[string]any{"error": "invalid credentials"})
		return
	}
	writeJSON(w, 200, map[string]any{"token": u.Token, "user": map[string]string{"id": u.ID, "username": u.Username}})
}

func (a *App) handleProfile(w http.ResponseWriter, r *http.Request, u *User) {
	writeJSON(w, 200, map[string]any{"user": map[string]string{"id": u.ID, "username": u.Username, "role": u.Role, "tenant": u.Tenant}})
}

// handleOrdersList supports ownership mining: GET /api/v1/orders returns the
// CALLER's own orders only (correctly protected collection).
func (a *App) handleOrdersList(w http.ResponseWriter, r *http.Request, u *User) {
	// POST on the collection creates an order for the caller (REST semantics;
	// used by the controlled creation workflow).
	if r.Method == "POST" {
		var body struct{ Item string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Item == "" {
			body.Item = "ot-test-item"
		}
		a.mu.Lock()
		a.orderSeq++
		id := fmt.Sprintf("o-8%03d", a.orderSeq)
		a.orders[id] = &order{ID: id, Owner: u.Username, Item: body.Item, Total: 42}
		a.mu.Unlock()
		writeJSON(w, 201, map[string]any{"order": map[string]any{"id": id, "owner": u.Username, "item": body.Item}})
		return
	}
	if r.Method != "GET" {
		notFound(w)
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	var list []*order
	for _, id := range sortedKeys(a.orders) {
		if a.orders[id].Owner == u.Username {
			list = append(list, a.orders[id])
		}
	}
	writeJSON(w, 200, map[string]any{"orders": list})
}

// VULNERABLE: any authenticated user can read any order (horizontal IDOR).
// POST creates an order for the caller (safe, non-destructive).
func (a *App) handleOrders(w http.ResponseWriter, r *http.Request, u *User) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/orders/")
	switch r.Method {
	case "GET":
		// NESTED + VULNERABLE: /api/v1/orders/{id}/notes returns notes for any
		// order to any authenticated user (no parent ownership check).
		if strings.HasSuffix(path, "/notes") {
			orderID := strings.TrimSuffix(path, "/notes")
			a.mu.RLock()
			notes := a.notes[orderID]
			a.mu.RUnlock()
			if notes == nil {
				notFound(w)
				return
			}
			writeJSON(w, 200, map[string]any{"order_id": orderID, "notes": notes})
			return
		}
		a.mu.RLock()
		o := a.orders[path]
		a.mu.RUnlock()
		if o == nil {
			notFound(w)
			return
		}
		writeJSON(w, 200, map[string]any{"order": o})
	case "POST":
		var body struct{ Item string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Item == "" {
			body.Item = "ot-test-item"
		}
		a.mu.Lock()
		a.orderSeq++
		id := fmt.Sprintf("o-8%03d", a.orderSeq)
		a.orders[id] = &order{ID: id, Owner: u.Username, Item: body.Item, Total: 42}
		a.mu.Unlock()
		writeJSON(w, 201, map[string]any{"order": map[string]any{"id": id, "owner": u.Username, "item": body.Item}})
	case "DELETE":
		// Present so the safety engine can prove it refuses destructive calls.
		notFound(w)
	default:
		notFound(w)
	}
}

// PROTECTED invoice endpoints (with nested payments) are handled below.
func (a *App) handleInvoices(w http.ResponseWriter, r *http.Request, u *User) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/invoices/")
	if strings.HasSuffix(rest, "/payments") {
		// NESTED + PROTECTED: parent invoice ownership enforced.
		invID := strings.TrimSuffix(rest, "/payments")
		a.mu.RLock()
		inv := a.invoices[invID]
		a.mu.RUnlock()
		if inv == nil {
			notFound(w)
			return
		}
		if inv.Owner != u.Username {
			notFound(w) // generic denial: hide existence from non-owners
			return
		}
		writeJSON(w, 200, map[string]any{"invoice_id": inv.ID, "payments": []map[string]any{{"id": "p-1", "amount": inv.Amount}}})
		return
	}
	a.mu.RLock()
	inv := a.invoices[rest]
	a.mu.RUnlock()
	if inv == nil || inv.Owner != u.Username {
		notFound(w) // correctly protected: generic not-found hides existence
		return
	}
	writeJSON(w, 200, map[string]any{"invoice": inv})
}

// VULNERABLE: any authenticated user reads any document; anonymous blocked.
func (a *App) handleDocuments(w http.ResponseWriter, r *http.Request, u *User) {
	a.mu.RLock()
	d := a.documents[strings.TrimPrefix(r.URL.Path, "/api/v1/documents/")]
	a.mu.RUnlock()
	if d == nil {
		notFound(w)
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"document": d}})
}

// Simulated cache deception over a PROTECTED endpoint: the owner's fetch
// caches the response against the full request URI; ANY later request to the
// same URI (even anonymous or non-owner) receives the cached owner body.
// On cache MISS the endpoint behaves protectively (owner-only), so a
// cache-busted retry exposes the artifact.
func (a *App) handleCachedDocs(w http.ResponseWriter, r *http.Request) {
	key := r.URL.RequestURI()
	u := a.userFrom(r) // resolve caller before any lock (RWMutex is not reentrant)
	a.mu.RLock()
	d := a.documents[strings.TrimPrefix(r.URL.Path, "/api/v1/cached-docs/")]
	a.mu.RUnlock()

	a.mu.Lock()
	if cached, ok := a.cache[key]; ok {
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(cached))
		return
	}
	a.mu.Unlock()

	if d == nil {
		notFound(w)
		return
	}
	if u == nil {
		writeJSON(w, 401, map[string]any{"error": "authentication required"})
		return
	}
	// MISS: protective behavior — only the owner receives the document.
	if u.Username != d.Owner {
		notFound(w) // generic denial hides existence
		return
	}
	bodyBytes, _ := json.Marshal(map[string]any{"data": map[string]any{"document": d}})
	a.mu.Lock()
	a.cache[key] = string(bodyBytes)
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("X-Cache", "MISS")
	w.WriteHeader(200)
	_, _ = w.Write(bodyBytes)
}

// VULNERABLE: no authentication at all; anyone can read any receipt.
func (a *App) handleReceipts(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	rc := a.receipts[strings.TrimPrefix(r.URL.Path, "/api/v1/receipts/")]
	a.mu.RUnlock()
	if rc == nil {
		notFound(w)
		return
	}
	writeJSON(w, 200, map[string]any{"receipt": rc})
}

// VULNERABLE (vertical): any authenticated user sees admin stats.
func (a *App) handleAdminStats(w http.ResponseWriter, r *http.Request, u *User) {
	writeJSON(w, 200, map[string]any{"stats": map[string]any{"orders_total": 7, "users_total": 3, "revenue": 12345}})
}

// PROTECTED (vertical): admin role required.
func (a *App) handleAdminUsers(w http.ResponseWriter, r *http.Request, u *User) {
	if u.Role != "admin" {
		writeJSON(w, 403, map[string]any{"error": "forbidden"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/users/")
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, usr := range a.users {
		if usr.ID == id {
			writeJSON(w, 200, map[string]any{"user": map[string]string{"id": usr.ID, "username": usr.Username, "role": usr.Role}})
			return
		}
	}
	notFound(w)
}

// VULNERABLE (cross-tenant): tenant scoping not enforced on file reads.
func (a *App) handleTenantFiles(w http.ResponseWriter, r *http.Request, u *User) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[1], "files/") {
		notFound(w)
		return
	}
	fid := strings.TrimPrefix(parts[1], "files/")
	a.mu.RLock()
	f := a.files[fid]
	a.mu.RUnlock()
	if f == nil {
		notFound(w)
		return
	}
	// BUG (intentional): the caller's tenant is never compared with f.Tenant.
	writeJSON(w, 200, map[string]any{"file": f})
}

// PROTECTED (nested + tenant): workspace reports are enforced.
func (a *App) handleWorkspaces(w http.ResponseWriter, r *http.Request, u *User) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/workspaces/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[1], "reports/") {
		notFound(w)
		return
	}
	wsID := parts[0]
	rid := strings.TrimPrefix(parts[1], "reports/")
	// caller tenant must match workspace prefix
	a.mu.RLock()
	rep := a.reports[rid]
	a.mu.RUnlock()
	if rep == nil || rep.Workspace != wsID {
		notFound(w)
		return
	}
	if (wsID == "ws-1" && u.Tenant != "t-acme") || (wsID == "ws-2" && u.Tenant != "t-globex") {
		notFound(w)
		return
	}
	writeJSON(w, 200, map[string]any{"report": rep})
}

// False-positive trap: echoes the requested id with generic content.
func (a *App) handleEcho(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/echo/")
	writeJSON(w, 200, map[string]any{"requested": id, "echo": "generic-content-not-object-data"})
}

// Soft-404 trap: generic 200 marketing page for ANY id, without echoing it.
// The owner baseline cannot contain the identifier → INCONCLUSIVE.
func (a *App) handleSoft404(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"page": "welcome", "content": "nothing-to-see-here", "footer": "marketing"})
}

// Cache trap (path-keyed): the cache key ignores query strings, so cache
// busting CANNOT rule out a shared-cache artifact. On miss the endpoint is
// owner-protective; on hit everyone receives the cached owner body.
func (a *App) handlePathCache(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Path // deliberately ignores the query string
	u := a.userFrom(r)
	a.mu.RLock()
	d := a.documents[strings.TrimPrefix(r.URL.Path, "/api/v1/pathcache/")]
	a.mu.RUnlock()

	a.mu.Lock()
	if cached, ok := a.cache[key]; ok {
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(cached))
		return
	}
	a.mu.Unlock()

	if d == nil {
		notFound(w)
		return
	}
	if u == nil {
		writeJSON(w, 401, map[string]any{"error": "authentication required"})
		return
	}
	if u.Username != d.Owner {
		notFound(w) // generic denial on miss: protective behavior
		return
	}
	bodyBytes, _ := json.Marshal(map[string]any{"data": map[string]any{"document": d}})
	a.mu.Lock()
	a.cache[key] = string(bodyBytes)
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Cache", "MISS")
	w.WriteHeader(200)
	_, _ = w.Write(bodyBytes)
}

// Vertical false-positive trap: an admin-looking page served identically to
// every caller including anonymous ones. A similarity-only detector would
// confirm a role bypass; the public-content probe must reject it.
func (a *App) handleAdminPublicInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"info": "public announcement", "audience": "everyone", "section": "about-us"})
}

// Redirects: /redirect/orders/{id} → in-scope object; /redirect/external →
// out-of-scope destination (the scanner must NOT follow it). Anonymous
// requests are refused like on any other protected surface.
func (a *App) handleRedirect(w http.ResponseWriter, r *http.Request) {
	if a.userFrom(r) == nil {
		writeJSON(w, 401, map[string]any{"error": "authentication required"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/redirect/")
	if strings.HasPrefix(path, "orders/") {
		id := strings.TrimPrefix(path, "orders/")
		w.Header().Set("Location", "/api/v1/orders/"+id)
		w.WriteHeader(302)
		return
	}
	if path == "external" {
		w.Header().Set("Location", "http://example.invalid/steal")
		w.WriteHeader(302)
		return
	}
	notFound(w)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- workflow laboratory (§25 fixture) -------------------------------------
//
// Deliberately vulnerable workflow surface:
//   - POST /api/v1/workflows/csrf            issues a flow token (any user)
//   - POST /api/v1/workflows/docs            creates a doc (owner = caller)
//   - GET  /api/v1/workflows/docs/{id}       VULNERABLE: any user reads any doc
//   - POST /api/v1/workflows/docs/{id}/approve  VULNERABLE: any user approves
//     any document (policy should be owner-only → business-flow bypass)
//   - DELETE /api/v1/workflows/docs/{id}     owner-only (safe cleanup works)

// handleWorkflowCSRF issues a single-use flow token for the caller.
func (a *App) handleWorkflowCSRF(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.wfSeq++
	token := fmt.Sprintf("csrf-%d-%d", a.wfSeq, time.Now().UnixNano())
	a.wfCSRF[token] = u.Username
	writeJSON(w, 200, map[string]string{"token": token})
}

// flowToken validates the X-Flow-Token header against an issued token.
func (a *App) flowToken(r *http.Request) (string, bool) {
	tok := r.Header.Get("X-Flow-Token")
	user, ok := a.wfCSRF[tok]
	return user, ok
}

// handleWorkflowDocs implements the workflow document surface.
func (a *App) handleWorkflowDocs(w http.ResponseWriter, r *http.Request, u *User) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/workflows/docs/")
	rest = strings.TrimSuffix(rest, "/")

	switch {
	case r.URL.Path == "/api/v1/workflows/docs" && r.Method == http.MethodPost:
		// Creation requires a valid flow token (CSRF correlation, §25).
		if _, ok := a.flowToken(r); !ok {
			w.WriteHeader(403)
			return
		}
		var body struct {
			Title string `json:"title"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.wfSeq++
		doc := &wfDoc{ID: fmt.Sprintf("wfdoc-%d", 7000+a.wfSeq), Owner: u.Username, Title: body.Title, Status: "draft"}
		a.wfDocs[doc.ID] = doc
		writeJSON(w, 201, map[string]any{"document": doc})

	case rest != "" && r.Method == http.MethodGet:
		a.mu.RLock()
		defer a.mu.RUnlock()
		doc, ok := a.wfDocs[rest]
		if !ok {
			w.WriteHeader(404)
			return
		}
		// VULNERABLE: no ownership check — any authenticated user can read.
		writeJSON(w, 200, map[string]any{"document": doc})

	case rest != "" && strings.HasSuffix(rest, "/approve") && r.Method == http.MethodPost:
		if _, ok := a.flowToken(r); !ok {
			w.WriteHeader(403)
			return
		}
		id := strings.TrimSuffix(rest, "/approve")
		a.mu.Lock()
		defer a.mu.Unlock()
		doc, ok := a.wfDocs[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		// VULNERABLE: any authenticated user may approve any document.
		// The intended policy (owner-approval-only) is not enforced — the
		// workflow battery must catch this as a business-flow bypass.
		doc.Status = "approved"
		writeJSON(w, 200, map[string]any{"document": doc})

	case rest != "" && r.Method == http.MethodDelete:
		if _, ok := a.flowToken(r); !ok {
			w.WriteHeader(403)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		doc, ok := a.wfDocs[rest]
		if !ok {
			w.WriteHeader(404)
			return
		}
		if doc.Owner != u.Username {
			w.WriteHeader(403) // cleanup is owner-only by design
			return
		}
		delete(a.wfDocs, rest)
		w.WriteHeader(204)

	default:
		w.WriteHeader(405)
	}
}

// ---- GraphQL laboratory surface (§26 fixture) -------------------------------
//
// POST /graphql with {"query": "...", "variables": {...}}:
//   - node(id) lookup: VULNERABLE — any authenticated user can read ANY
//     document node (object-level authorization missing at the resolver).
//   - documents list: returns all documents to any authenticated user.
//   - deleteDoc mutation: admin-only (protected mutation, 403 otherwise).

// handleGraphQL implements a minimal deterministic GraphQL-over-HTTP lab.
func (a *App) handleGraphQL(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Query) == "" {
		writeJSON(w, 400, map[string]any{"errors": []map[string]string{{"message": "invalid GraphQL request"}}})
		return
	}
	q := body.Query

	switch {
	case strings.Contains(q, "deleteDoc"):
		// Protected mutation: admin role required.
		if u.Role != "admin" {
			writeJSON(w, 403, map[string]any{"errors": []map[string]string{{"message": "admin role required"}}})
			return
		}
		id, _ := body.Variables["id"].(string)
		a.mu.Lock()
		delete(a.documents, id)
		a.mu.Unlock()
		writeJSON(w, 200, map[string]any{"data": map[string]any{"deleteDoc": true}})

	case strings.Contains(q, "documents"):
		a.mu.RLock()
		list := make([]document, 0, len(a.documents))
		for _, d := range a.documents {
			list = append(list, *d)
		}
		a.mu.RUnlock()
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		writeJSON(w, 200, map[string]any{"data": map[string]any{"documents": list}})

	case strings.Contains(q, "node"):
		id, _ := body.Variables["id"].(string)
		if id == "" {
			// inline argument: node(id: "doc-3001")
			if i := strings.Index(q, "node(id:"); i >= 0 {
				rest := q[i+len("node(id:"):]
				if j := strings.Index(rest, "\""); j >= 0 {
					rest = rest[j+1:]
					if k := strings.Index(rest, "\""); k >= 0 {
						id = rest[:k]
					}
				}
			}
		}
		a.mu.RLock()
		doc, ok := a.documents[id]
		a.mu.RUnlock()
		if !ok {
			writeJSON(w, 200, map[string]any{
				"data":   map[string]any{"node": nil},
				"errors": []map[string]string{{"message": "node not found: " + id}},
			})
			return
		}
		// VULNERABLE: the resolver performs NO ownership check — any
		// authenticated user can read any document node.
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"node": map[string]string{"id": doc.ID, "owner": doc.Owner, "title": doc.Title},
		}})

	default:
		writeJSON(w, 200, map[string]any{"errors": []map[string]string{{"message": "unsupported operation"}}})
	}
}
