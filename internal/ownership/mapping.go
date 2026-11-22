// Ownership mapping: builds the registry from user-declared mappings,
// controlled creation workflows and listing-membership inference.
package ownership

import (
	"context"
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/util"
)

// Mapper builds ownership records.
type Mapper struct {
	Cfg    *config.Config
	Client *httpclient.Client
	Auth   *auth.Manager
	Evid   *evidence.Engine
	Log    *logger.Logger
	Scope  ScopeChecker
}

// ScopeChecker is the minimal scope interface needed (avoids import cycle
// concerns and eases testing).
type ScopeChecker interface {
	Check(method, raw string) Decision
}

// Decision mirrors scope.Decision.
type Decision struct {
	Allowed bool
	Reason  string
}

// Build maps declared objects, runs the creation workflow when enabled, and
// mines owned collections. Returns the registry and human-readable notes.
func (m *Mapper) Build(ctx context.Context, sessionID string) (*Registry, []string) {
	reg := NewRegistry()
	var notes []string

	for i, d := range m.Cfg.Objects.Declared {
		for _, id := range d.Identifiers {
			url := strings.Replace(d.URL, "{id}", id, 1)
			rec := &Record{
				Resource:     orDefault(d.Resource, "object"),
				Identifier:   id,
				OwnerProfile: d.Profile,
				State:        StateDeclared,
				Confidence:   0.8,
				Tenant:       d.Tenant,
				EndpointPath: url,
				SessionID:    sessionID,
				Provenance:   []endpoints.SourceRef{{Kind: endpoints.SourceConfig, Location: fmt.Sprintf("objects.declared[%d]", i)}},
				Notes:        "user-declared ownership mapping",
			}
			reg.Upsert(rec)
		}
		notes = append(notes, fmt.Sprintf("declared %d object(s) owned by profile %q", len(d.Identifiers), d.Profile))
	}

	if m.Cfg.Objects.Creation.Enabled {
		n, err := m.runCreation(ctx, sessionID, reg)
		if err != nil {
			notes = append(notes, "creation workflow failed: "+err.Error())
		} else {
			notes = append(notes, fmt.Sprintf("creation workflow confirmed %d new object(s)", n))
		}
	}

	for _, col := range m.Cfg.Objects.MineCollections {
		n, err := m.mineCollection(ctx, sessionID, reg, col)
		if err != nil {
			notes = append(notes, fmt.Sprintf("collection mining %s failed: %v", col.URL, err))
		} else {
			notes = append(notes, fmt.Sprintf("mined %d candidate object(s) from collection %s", n, col.URL))
		}
	}
	return reg, notes
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// runCreation executes the controlled creation workflow per configured
// profile. Preconditions (write methods allowed, scope inclusion) were
// validated at config load; scope is re-checked here before every request.
func (m *Mapper) runCreation(ctx context.Context, sessionID string, reg *Registry) (int, error) {
	w := m.Cfg.Objects.Creation
	method := strings.ToUpper(orDefault(w.Method, "POST"))
	created := 0
	for _, profile := range w.Profiles {
		if d := m.Scope.Check(method, w.Endpoint); !d.Allowed {
			return created, fmt.Errorf("creation endpoint out of scope: %s", d.Reason)
		}
		headers, err := m.Auth.Headers(profile)
		if err != nil {
			return created, err
		}
		body := []byte(w.BodyTemplate)
		x := m.Client.Do(ctx, method, w.Endpoint, httpclient.Options{
			Headers: headers, Body: body, ContentType: orDefault(w.ContentType, "application/json"),
		})
		if x == nil || !x.Succeeded() {
			return created, fmt.Errorf("create as %s: %s", profile, briefHTTP(x))
		}
		if x.Status >= 300 {
			return created, fmt.Errorf("create as %s: HTTP %d — object not created, ownership not established", profile, x.Status)
		}
		id, ok := extractID(x.Body, w.ExtractField)
		if !ok || id == "" {
			return created, fmt.Errorf("create as %s: field %q not found in response body", profile, w.ExtractField)
		}
		itemURL := w.Endpoint
		if w.ItemURLTemplate != "" {
			itemURL = strings.Replace(w.ItemURLTemplate, "{{id}}", id, 1)
		} else if strings.Contains(w.Endpoint, "{id}") {
			itemURL = strings.Replace(w.Endpoint, "{id}", id, 1)
		} else {
			itemURL = strings.TrimSuffix(w.Endpoint, "/") + "/" + id
		}
		rec := &Record{
			Resource:     "object",
			Identifier:   id,
			OwnerProfile: profile,
			State:        StateConfirmed,
			Confidence:   1.0,
			EndpointPath: itemURL,
			SessionID:    sessionID,
			Provenance:   []endpoints.SourceRef{{Kind: endpoints.SourceConfig, Location: "objects.creation"}},
			Notes:        "created via controlled creation workflow",
		}
		reg.Upsert(rec)
		created++
		if m.Evid != nil {
			_, _ = m.Evid.Capture("", sessionID, evidence.KindOwnershipProof,
				fmt.Sprintf("object %s created by profile %s", id, profile),
				map[string]any{"owner": profile, "extracted_id": id, "endpoint": w.Endpoint,
					"status": x.Status, "response_body": x.Body})
		}
		m.Log.Infof("ownership: created object %s owned by %s", id, profile)
	}
	return created, nil
}

// mineCollection GETs a collection endpoint as its profile and records every
// identifier found in the listing as INFERRED ownership (listing membership
// is evidence, not proof).
func (m *Mapper) mineCollection(ctx context.Context, sessionID string, reg *Registry, col config.Collection) (int, error) {
	// The collection URL must name its owning profile explicitly via the
	// profile field... it doesn't. The user must provide one collection per
	// profile via url containing the profile marker; instead we require the
	// collection to be configured per-profile: profile inferred from mapping.
	// Configuration shape: mine_collections entries each carry `url` and the
	// profile is provided in `resource`? No — extend config: Profile field.
	profile := col.Profile
	if profile == "" {
		return 0, fmt.Errorf("mine_collections entry requires a profile field")
	}
	if d := m.Scope.Check("GET", col.URL); !d.Allowed {
		return 0, fmt.Errorf("collection out of scope: %s", d.Reason)
	}
	headers, err := m.Auth.Headers(profile)
	if err != nil {
		return 0, err
	}
	x := m.Client.Do(ctx, "GET", col.URL, httpclient.Options{Headers: headers})
	if x == nil || !x.Succeeded() || x.Status >= 300 {
		return 0, fmt.Errorf("collection request failed: %s", briefHTTP(x))
	}
	v := util.DecodeJSONLoose([]byte(x.Body))
	if v == nil {
		return 0, fmt.Errorf("collection response is not JSON")
	}
	fields := col.IDFields
	if len(fields) == 0 {
		fields = []string{"id", "uuid", "identifier", "order_id", "invoice_id", "document_id", "file_id", "report_id"}
	}
	count := 0
	seen := map[string]bool{}
	var walk func(node any)
	walk = func(node any) {
		switch t := node.(type) {
		case map[string]any:
			for _, f := range fields {
				if val, ok := util.GetPath(t, f); ok {
					id := util.FirstString(val)
					if id != "" && !seen[id] {
						seen[id] = true
						res := orDefault(col.Resource, "object")
						rec := &Record{
							Resource:     res,
							Identifier:   id,
							OwnerProfile: profile,
							State:        StateInferred,
							Confidence:   0.7,
							EndpointPath: itemURLOf(col.URL, id),
							SessionID:    sessionID,
							Provenance:   []endpoints.SourceRef{{Kind: endpoints.SourceConfig, Location: "mine_collections"}},
							Notes:        "inferred from listing membership in " + col.URL,
						}
						reg.Upsert(rec)
						count++
					}
				}
			}
			// recurse
			for _, val := range t {
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(v)
	if m.Evid != nil && count > 0 {
		_, _ = m.Evid.Capture("", sessionID, evidence.KindOwnershipProof,
			fmt.Sprintf("collection %s mined for profile %s (%d ids)", col.URL, profile, count),
			map[string]any{"profile": profile, "url": col.URL, "count": count})
	}
	return count, nil
}

func itemURLOf(collectionURL, id string) string {
	base := collectionURL
	if q := strings.IndexByte(base, '?'); q > 0 {
		base = base[:q]
	}
	return strings.TrimSuffix(base, "/") + "/" + id
}

func extractID(body, field string) (string, bool) {
	v := util.DecodeJSONLoose([]byte(body))
	if v == nil {
		return "", false
	}
	if val, ok := util.GetPath(v, field); ok {
		s := util.FirstString(val)
		return s, s != ""
	}
	return "", false
}

func briefHTTP(x *httpclient.Exchange) string {
	if x == nil {
		return "no response"
	}
	if x.Err != "" {
		return x.Err
	}
	return fmt.Sprintf("HTTP %d", x.Status)
}
