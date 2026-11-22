// GraphQL battery orchestration (§26): harvested operations are matched to
// owned objects by identifier and verified object-level by the engine.
package scan

import (
	"context"
	"fmt"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/graphql"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/verification"
)

// runGraphQL verifies every harvested operation that addresses a mapped
// object. Operations without a mapped object are noted, never guessed.
func (r *Runner) runGraphQL(ctx context.Context, sessionID string, reg *ownership.Registry, ops []graphql.Operation, sum *Summary) {
	byID := map[string]*ownership.Record{}
	for _, rec := range reg.List() {
		if rec.Identifier != "" {
			byID[rec.Identifier] = rec
		}
	}
	for _, op := range ops {
		if findingsBudgetExhausted(sum, r.Cfg.Verification) || ctx.Err() != nil {
			return
		}
		matched := false
		for _, ident := range graphqlIdentifiers(op) {
			rec, ok := byID[ident]
			if !ok || rec.OwnerProfile == "" {
				continue
			}
			matched = true
			category := finding.CatHorizontal
			if rec.Tenant != "" {
				category = finding.CatCrossTenant
			}
			item := verification.TestItem{
				URL:        op.Endpoint,
				Method:     "POST",
				Resource:   rec.Resource,
				Identifier: rec.Identifier,
				Owner:      rec.OwnerProfile,
				OwnerState: rec.State,
				Tenant:     rec.Tenant,
				Category:   category,
				EndpointID: "graphql",
			}
			f := r.Verif.VerifyGraphQL(ctx, op, item)
			sum.ChecksExecuted++
			if f != nil {
				sum.Findings[string(f.State)]++
			}
		}
		if !matched {
			sum.Notes = append(sum.Notes, fmt.Sprintf(
				"GraphQL operation at %s addresses no mapped object — not tested (no fabricated ownership)", op.Endpoint))
		}
	}
}

// graphqlIdentifiers returns the object-identifier-like values an operation
// addresses (query text + string variables).
func graphqlIdentifiers(op graphql.Operation) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || len(s) > 128 || seen[s] || !endpoints.LooksIdentifierLike(s) {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(op.Query)
	for _, v := range op.Variables {
		switch t := v.(type) {
		case string:
			add(t)
		case []any:
			for _, item := range t {
				if s, ok := item.(string); ok {
					add(s)
				}
			}
		case map[string]any:
			for _, item := range t {
				if s, ok := item.(string); ok {
					add(s)
				}
			}
		}
	}
	return out
}
