// Package discovery implements target discovery from explicit URLs, HAR 1.2
// captures, OpenAPI 3.x / Swagger 2.x documents and limited HTML/JS crawling.
// All discovery results are scope-filtered and carry provenance.
package discovery

import (
	"fmt"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/graphql"
)

// ResponseSample captures observed traffic responses for later object mining
// and ownership attribution (profile tagging comes from the HAR profile
// header, or the user-declared mapping).
type ResponseSample struct {
	EndpointKey string `json:"endpoint_key"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Profile     string `json:"profile,omitempty"` // profile that captured this traffic
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"` // redacted, truncated
}

// Result is the discovery output.
type Result struct {
	Endpoints *endpoints.Set
	Samples   []ResponseSample
	Notes     []string
	// GraphQLOps are the GraphQL operations harvested from HAR traffic (§26).
	GraphQLOps []graphql.Operation
}

func NewResult() *Result {
	return &Result{Endpoints: endpoints.NewSet()}
}

func (r *Result) Note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// BuildFromURL creates an endpoint from a concrete URL (thin alias to the
// endpoints package constructor).
func BuildFromURL(method, raw string, srcKind endpoints.SourceKind, srcLoc string) (*endpoints.Endpoint, bool) {
	return endpoints.BuildFromURL(method, raw, srcKind, srcLoc)
}
