// Package scan orchestrates a full authorization testing run:
// discovery → identity verification → ownership mapping → test-item
// selection → concurrent cross-account testing → persisted findings.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/discovery"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/objects"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
	"github.com/Lutfifakee-Project/owntrace/internal/storage"
	"github.com/Lutfifakee-Project/owntrace/internal/verification"
)

// Summary is the run result reported to the CLI.
type Summary struct {
	SessionID      string         `json:"session_id"`
	DryRun         bool           `json:"dry_run"`
	Endpoints      int            `json:"endpoints"`
	Objects        int            `json:"objects"`
	Findings       map[string]int `json:"findings"`
	Notes          []string       `json:"notes"`
	Requests       int64          `json:"requests_sent"`
	IdentityOK     bool           `json:"identity_separation_ok"`
	OwnershipNotes []string       `json:"ownership_notes,omitempty"`
	// Authorization coverage accounting (33): planned vs executed checks.
	ChecksPlanned  int `json:"checks_planned"`
	ChecksExecuted int `json:"checks_executed"`
	SafetySkipped  int `json:"safety_skipped"`
}

// Runner executes scans.
type Runner struct {
	Cfg    *config.Config
	Scope  *scope.Checker
	Client *httpclient.Client
	Auth   *auth.Manager
	Log    *logger.Logger
	DB     *storage.DB
	Evid   *evidence.Engine
	Verif  *verification.Engine
}

// Run executes the pipeline. dryRun performs discovery/ownership mapping and
// prints the plan without sending verification requests beyond discovery
// (discovery itself only crawls when the crawl source is enabled).
func (r *Runner) Run(ctx context.Context, dryRun bool) (*Summary, error) {
	sum := &Summary{Findings: map[string]int{}}

	cfgJSON, _ := json.Marshal(r.Cfg.RedactedCopy())
	sessionID, err := r.DB.BeginSession(orDefaultName(r.Cfg.Session.Name), string(cfgJSON))
	if err != nil {
		return nil, fmt.Errorf("begin session: %w", err)
	}
	sum.SessionID = sessionID
	r.Verif.Session = sessionID
	r.Log.Infof("session %s started", sessionID)
	defer func() {
		if err != nil {
			_ = r.DB.FinishSession(sessionID, storage.SessionInterrupted)
		}
	}()

	// ---- discovery or stored inventory ----
	// Empty discovery sources (--no-discover) reuse the endpoint inventory of
	// the most recent completed session. Missing, stale or scope-incompatible
	// inventories are REJECTED instead of silently tested (CLI spec §5).
	var res *discovery.Result
	if len(r.Cfg.Discovery.Sources) == 0 {
		res, err = r.loadStoredInventory(sessionID)
		if err != nil {
			return sum, err
		}
	} else {
		res, err = discovery.Run(ctx, r.Cfg, r.Client, r.Scope, r.Log)
		if err != nil {
			return sum, fmt.Errorf("discovery: %w", err)
		}
	}
	sum.Endpoints = res.Endpoints.Len()
	for _, n := range res.Notes {
		sum.Notes = append(sum.Notes, n)
		_ = r.DB.Audit(sessionID, "info", "discovery_note", redact.Text(n))
	}
	for _, ep := range res.Endpoints.List() {
		if err := r.DB.SaveEndpoint(sessionID, ep); err != nil {
			r.Log.Warnf("save endpoint: %v", err)
		}
	}
	r.Log.Infof("discovery: %d unique in-scope endpoints", res.Endpoints.Len())

	// HAR samples with profile tags create inferred ownership directly.
	inferred := inferFromSamples(sessionID, res, r.Cfg)

	// ---- identity separation ----
	profiles := r.Auth.Names()
	sep := r.Auth.VerifySeparation(ctx, r.Client, profiles)
	sum.IdentityOK = sep.Verified
	if _, aerr := r.Evid.Capture("", sessionID, evidence.KindVerification, "identity separation (all profiles)", sep); aerr != nil {
		r.Log.Warnf("evidence capture failed: %v", aerr)
	}
	if !sep.Verified {
		summary := "identity separation NOT verified: " + sep.Detail
		sum.Notes = append(sum.Notes, summary)
		_ = r.DB.Audit(sessionID, "warn", "identity_separation", summary)
		if r.Cfg.Verification.RequireIdentitySeparation {
			// Cross-account verdicts would be meaningless; stop before testing.
			sum.Notes = append(sum.Notes, "cross-account testing aborted (require_identity_separation=true)")
			_ = r.DB.FinishSession(sessionID, storage.SessionCompleted)
			return sum, nil
		}
	}

	// ---- ownership mapping ----
	mapper := &ownership.Mapper{
		Cfg: r.Cfg, Client: r.Client, Auth: r.Auth, Evid: r.Evid, Log: r.Log, Scope: scopeAdapter{r.Scope},
	}
	reg, ownershipNotes := mapper.Build(ctx, sessionID)
	for _, rec := range inferred {
		reg.Upsert(rec)
	}
	sum.OwnershipNotes = ownershipNotes
	// ---- operator workflows (§25): controlled creation + business flows ----
	if len(r.Cfg.Workflows.Files) > 0 {
		if dryRun {
			sum.Notes = append(sum.Notes, fmt.Sprintf("would execute %d workflow file(s) (state-changing steps skipped in dry-run)", len(r.Cfg.Workflows.Files)))
		} else if werr := r.runWorkflows(ctx, sessionID, reg, sum); werr != nil {
			sum.Notes = append(sum.Notes, "workflows: "+werr.Error())
		}
	}
	records := reg.List()
	sum.Objects = len(records)
	for _, rec := range records {
		row := &storage.ObjectRow{
			ID: rec.ID, SessionID: sessionID, Resource: rec.Resource, Identifier: rec.Identifier,
			EndpointID: rec.EndpointID, EndpointPath: rec.EndpointPath, OwnerProfile: rec.OwnerProfile,
			OwnerState: string(rec.State), Confidence: rec.Confidence, Tenant: rec.Tenant,
			Provenance: provenanceJSON(rec), CreatedAt: rec.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if err := r.DB.SaveObject(row); err != nil {
			r.Log.Warnf("save object: %v", err)
		}
	}
	r.Log.Infof("ownership: %d object record(s) mapped", len(records))

	// ---- build test items ----
	items := buildItems(reg, res, r.Cfg)
	verticalCount := 0
	if r.Cfg.Verification.VerticalTest {
		for _, ep := range res.Endpoints.List() {
			if ep.Adminish {
				verticalCount += len(concreteURLs(ep))
			}
		}
	}
	r.Log.Infof("test plan: %d object test(s), %d vertical endpoint URL(s)",
		len(items.objectItems), verticalCount)
	sum.ChecksPlanned += len(items.objectItems)
	if r.Cfg.Verification.AnonymousTest {
		sum.ChecksPlanned += len(items.objectItems)
	}
	if verticalCount > 0 {
		nonAdmins := 0
		for _, name := range r.Auth.Names() {
			if p, perr := r.Auth.Profile(name); perr == nil && !strings.EqualFold(p.Role, "admin") {
				nonAdmins++
			}
		}
		sum.ChecksPlanned += verticalCount * nonAdmins
	}
	if len(r.Cfg.Workflows.Files) > 0 {
		sum.ChecksPlanned++ // business-flow battery per workflow file set
	}
	if len(res.GraphQLOps) > 0 {
		sum.ChecksPlanned += len(res.GraphQLOps)
	}

	if dryRun {
		sum.DryRun = true
		if len(res.GraphQLOps) > 0 {
			sum.Notes = append(sum.Notes, fmt.Sprintf("would run the GraphQL battery on %d harvested operation(s)", len(res.GraphQLOps)))
		}
		for _, it := range items.objectItems {
			sum.Notes = append(sum.Notes, fmt.Sprintf("would test %s: %s %s (owner=%s, %s)", it.Category, it.Method, redact.URL(it.URL), it.Owner, it.OwnerState))
		}
		_ = r.DB.FinishSession(sessionID, storage.SessionCompleted)
		return sum, nil
	}

	// ---- vertical testing (role matrix) ----
	// Every privileged endpoint is tested against EVERY non-privileged
	// profile, producing a per-role authorization matrix instead of a single
	// first-attacker probe.
	if r.Cfg.Verification.VerticalTest {
		admin := ""
		var nonAdmins []string
		for _, name := range r.Auth.Names() {
			p, err := r.Auth.Profile(name)
			if err != nil {
				continue
			}
			if strings.EqualFold(p.Role, "admin") {
				admin = name
			} else {
				nonAdmins = append(nonAdmins, name)
			}
		}
		for _, ep := range res.Endpoints.List() {
			if !ep.Adminish || admin == "" || len(nonAdmins) == 0 || findingsBudgetExhausted(sum, r.Cfg.Verification) {
				continue
			}
			for _, u := range concreteURLs(ep) {
				if d := r.Scope.Check(ep.Method, u); !d.Allowed {
					continue
				}
				for _, attacker := range nonAdmins {
					if findingsBudgetExhausted(sum, r.Cfg.Verification) {
						break
					}
					f := r.Verif.VerifyVerticalPair(ctx, u, ep.Method, ep, admin, attacker)
					// vertical loop runs sequentially before the worker pool
					sum.ChecksExecuted++
					if f != nil {
						sum.Findings[string(f.State)]++
					}
				}
			}
		}
	}

	// ---- object testing (bounded concurrency) ----
	workers := r.Cfg.Limits.Concurrency
	if workers < 1 {
		workers = 1
	}
	itemCh := make(chan verification.TestItem)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range itemCh {
				mu.Lock()
				over := findingsBudgetExhausted(sum, r.Cfg.Verification)
				mu.Unlock()
				if over || ctx.Err() != nil {
					continue
				}
				f := r.Verif.VerifyItem(ctx, it)
				mu.Lock()
				sum.ChecksExecuted++
				sum.Findings[string(f.State)]++
				mu.Unlock()
				// anonymous follow-up test
				if r.Cfg.Verification.AnonymousTest && it.Owner != auth.AnonymousProfile && ctx.Err() == nil {
					af := r.Verif.VerifyAnonymous(ctx, it)
					mu.Lock()
					sum.ChecksExecuted++
					sum.Findings[string(af.State)]++
					mu.Unlock()
				}
			}
		}()
	}
	for _, it := range items.objectItems {
		if ctx.Err() != nil {
			break
		}
		itemCh <- it
	}
	close(itemCh)
	wg.Wait()

	if cerr := ctx.Err(); cerr != nil {
		err = fmt.Errorf("scan cancelled: %w", cerr)
		return sum, err
	}

	// ---- GraphQL battery (§26) ----
	if len(res.GraphQLOps) > 0 && r.Cfg.Verification.GraphQLTestingEnabled() {
		r.runGraphQL(ctx, sessionID, reg, res.GraphQLOps, sum)
	}

	// ---- sensitive business-flow testing (§24) ----
	// Flows with a declared policy are re-executed as an unauthorized
	// principal; a completed unauthorized flow is evaluated by the
	// business-flow verification battery (§29).
	if len(r.Cfg.Workflows.Files) > 0 {
		r.runBusinessFlows(ctx, sessionID, sum)
	}

	// ---- finish ----
	sum.Requests = r.Scope.UsedRequests()
	_ = r.DB.Audit(sessionID, "info", "scan_complete", fmt.Sprintf("findings=%v", sum.Findings))
	if ferr := r.DB.FinishSession(sessionID, storage.SessionCompleted); ferr != nil {
		r.Log.Warnf("finish session: %v", ferr)
	}
	return sum, nil
}

// loadStoredInventory reuses the endpoint inventory of the most recent
// completed session (--no-discover). The inventory must exist, be fresh
// enough to trust, and remain scope-compatible with the CURRENT scope: any
// failure is an error, never a silent fallback to scanning stale targets.
func (r *Runner) loadStoredInventory(currentSession string) (*discovery.Result, error) {
	sessions, err := r.DB.ListSessions()
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	var prev *storage.Session
	for i := range sessions {
		if sessions[i].ID != currentSession && sessions[i].Status == storage.SessionCompleted {
			prev = &sessions[i]
			break
		}
	}
	if prev == nil {
		return nil, fmt.Errorf("no previous completed session inventory found — run a full scan or discovery first (remove --no-discover)")
	}
	if started, perr := time.Parse(time.RFC3339, prev.StartedAt); perr == nil {
		maxAge := time.Duration(r.Cfg.Discovery.InventoryMaxAgeHours) * time.Hour
		if age := time.Since(started); age > maxAge {
			return nil, fmt.Errorf("inventory from session %s is stale (age %d h > %d h) — rerun discovery (remove --no-discover)",
				prev.ID, int(age.Hours()), int(maxAge.Hours()))
		}
	}
	rows, err := r.DB.ListEndpoints(prev.ID)
	if err != nil {
		return nil, fmt.Errorf("list stored endpoints: %w", err)
	}
	res := discovery.NewResult()
	kept, rejected := 0, 0
	for _, ep := range rows {
		if !r.Scope.Check(ep.Method, sampleURL(ep)).Allowed {
			rejected++
			continue
		}
		res.Endpoints.Add(ep)
		kept++
	}
	if kept == 0 {
		return nil, fmt.Errorf("stored inventory from session %s has no scope-compatible endpoints — scope changed; rerun discovery", prev.ID)
	}
	res.Note("reused %d scope-compatible endpoint(s) from session %s (--no-discover; %d out-of-scope entries dropped)", kept, prev.ID, rejected)
	return res, nil
}

// sampleURL picks the best testable URL for a stored endpoint: an observed
// sample when present, otherwise the reconstructed scheme+host+path.
func sampleURL(ep *endpoints.Endpoint) string {
	if len(ep.Samples) > 0 {
		return ep.Samples[0]
	}
	host := ep.Host
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	return host + ep.Path
}

func findingsBudgetExhausted(sum *Summary, cfg config.Verification) bool {
	total := 0
	for _, n := range sum.Findings {
		total += n
	}
	return total >= cfg.MaxFindings
}

func orDefaultName(s string) string {
	if strings.TrimSpace(s) == "" {
		return "scan"
	}
	return s
}

// scopeAdapter adapts *scope.Checker to the Mapper's interface.
type scopeAdapter struct{ c *scope.Checker }

func (a scopeAdapter) Check(method, raw string) ownership.Decision {
	d := a.c.Check(method, raw)
	return ownership.Decision{Allowed: d.Allowed, Reason: d.Reason}
}

func provenanceJSON(rec *ownership.Record) string {
	b, _ := json.Marshal(rec.Provenance)
	return string(b)
}

// inferFromSamples creates inferred ownership records from HAR traffic that
// was captured with a profile tag and returned the object data.
func inferFromSamples(sessionID string, res *discovery.Result, cfg *config.Config) []*ownership.Record {
	var out []*ownership.Record
	for _, s := range res.Samples {
		if s.Profile == "" || s.Status < 200 || s.Status >= 300 || s.Body == "" {
			continue
		}
		// Only item responses (URL contains an identifier) are ownership evidence.
		for _, c := range objects.FromResponse(s.EndpointKey, []byte(s.Body), s.ContentType, []endpoints.SourceRef{{Kind: endpoints.SourceHAR, Location: s.URL}}) {
			if c.Location != objects.LocResponse && c.Example == "" {
				continue
			}
			// The response belongs to the URL that produced it; ownership of the
			// *item* URL is what matters. Only treat path-ish identifiers on the
			// same URL as item identifiers.
			ep, ok := res.Endpoints.LookupByID(s.EndpointKey)
			if !ok || ep == nil {
				continue
			}
			itemURL := s.URL
			rec := &ownership.Record{
				Resource:     c.Resource,
				Identifier:   c.Example,
				OwnerProfile: s.Profile,
				State:        ownership.StateInferred,
				Confidence:   0.6,
				EndpointPath: itemURL,
				SessionID:    sessionID,
				Provenance:   []endpoints.SourceRef{{Kind: endpoints.SourceHAR, Location: "traffic tagged " + s.Profile}},
				Notes:        "inferred from profile-tagged HAR traffic",
			}
			out = append(out, rec)
		}
	}
	return out
}

// testItems is the constructed test plan.
type testItems struct {
	objectItems []verification.TestItem
}

// buildItems turns ownership records into concrete test items.
func buildItems(reg *ownership.Registry, res *discovery.Result, cfg *config.Config) *testItems {
	out := &testItems{}
	seen := map[string]bool{}
	// profile -> tenant (from declared/inferred records)
	tenantOf := map[string]string{}
	for _, rec := range reg.List() {
		if rec.Tenant != "" {
			tenantOf[rec.OwnerProfile] = rec.Tenant
		}
	}
	for _, rec := range reg.List() {
		if rec.EndpointPath == "" || rec.Identifier == "" {
			continue
		}
		url := rec.EndpointPath
		if strings.Contains(url, "{") {
			continue // template without a concrete value
		}
		category := finding.CatHorizontal
		if rec.Tenant != "" {
			category = finding.CatCrossTenant
		} else if countPathPlaceholders(url) >= 2 || isNestedPath(url) {
			category = finding.CatNested
		}
		it := verification.TestItem{
			URL:        url,
			Method:     "GET",
			Resource:   rec.Resource,
			Identifier: rec.Identifier,
			Owner:      rec.OwnerProfile,
			OwnerState: rec.State,
			Tenant:     rec.Tenant,
			Category:   category,
		}
		key := string(category) + "|" + url + "|" + rec.OwnerProfile
		if !seen[key] {
			seen[key] = true
			out.objectItems = append(out.objectItems, it)
		}
	}
	return out
}

// nestedSuffixes are child-resource path segments that indicate nested
// resource addressing (/parent/{id}/children).
var nestedSuffixes = map[string]bool{
	"notes": true, "payments": true, "items": true, "children": true,
	"comments": true, "attachments": true, "lines": true, "subtasks": true,
	"members": true, "settings": true, "documents": true, "files": true,
}

// isNestedPath reports whether a concrete URL addresses a child resource
// nested under an identifier (/orders/o-1001/notes). The child-resource
// segment must directly follow an identifier-like segment, so resource
// collections named "documents" or "files" are not misclassified.
func isNestedPath(url string) bool {
	prevIdentifier := false
	for _, seg := range strings.Split(url, "/") {
		if seg == "" {
			continue
		}
		if prevIdentifier && nestedSuffixes[strings.ToLower(seg)] {
			return true
		}
		prevIdentifier = endpoints.LooksIdentifierLike(seg)
	}
	return false
}

// countPathPlaceholders counts identifier-looking concrete segments in a URL.
func countPathPlaceholders(url string) int {
	n := 0
	for _, seg := range strings.Split(url, "/") {
		if seg == "" {
			continue
		}
		if endpoints.LooksIdentifierLike(seg) {
			n++
		}
	}
	return n
}

// concreteURLs renders testable URLs for an endpoint using sample values.
func concreteURLs(ep *endpoints.Endpoint) []string {
	var out []string
	if len(ep.Samples) > 0 {
		for _, s := range ep.Samples {
			out = append(out, s)
			if len(out) >= 3 {
				break
			}
		}
	}
	if len(out) == 0 {
		vals := map[string]string{}
		for _, p := range ep.PathParams() {
			vals[p] = "1"
		}
		if u, missing, err := ep.FillURL(vals); err == nil && len(missing) == 0 {
			out = append(out, u)
		}
	}
	return out
}
