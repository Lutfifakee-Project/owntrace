// Package objects models candidate authorization-relevant objects (things a
// user owns and another user must not access) discovered in endpoints, traffic
// and responses.
package objects

import (
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
)

// Location tells where in a request/response an object reference was found.
type Location string

const (
	LocPath     Location = "path"
	LocQuery    Location = "query"
	LocBody     Location = "body"
	LocResponse Location = "response"
)

// Shape classifies identifier format, used to craft verification inputs.
type Shape string

const (
	ShapeNumeric Shape = "numeric"
	ShapeUUID    Shape = "uuid"
	ShapeHex     Shape = "hex"
	ShapeOpaque  Shape = "opaque"
	ShapeUnknown Shape = "unknown"
)

// Candidate is a discovered object reference that may be ownership-sensitive.
type Candidate struct {
	ID         string                `json:"id"`          // stable key
	EndpointID string                `json:"endpoint_id"` // endpoint it belongs to
	Resource   string                `json:"resource"`    // guessed resource type, e.g. "order"
	ParamName  string                `json:"param_name"`  // placeholder / field name
	Location   Location              `json:"location"`    // where it lives
	Example    string                `json:"example"`     // observed value (if any)
	Shape      Shape                 `json:"shape"`       // identifier shape
	Confidence float64               `json:"confidence"`  // 0..1 heuristic confidence
	Sources    []endpoints.SourceRef `json:"sources"`     // provenance
}

// Key builds the stable candidate key.
func (c *Candidate) Key() string {
	return c.EndpointID + "|" + string(c.Location) + "|" + c.ParamName
}

// idParamHints are parameter name fragments that signal an object identifier.
// A match raises confidence; absence does not remove an object from
// consideration because identifiers are frequently named after resources.
var idParamHints = []string{
	"id", "uuid", "guid", "ident", "ref", "reference", "key", "number", "no",
	"code", "slug", "uid",
}

// tenantHints are name fragments signaling tenant scoping.
var tenantHints = []string{"tenant", "org", "organization", "workspace", "account", "company", "team", "project"}

// IsTenantParam reports whether a parameter name looks like a tenant selector.
func IsTenantParam(name string) bool {
	l := strings.ToLower(name)
	for _, h := range tenantHints {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// IsIDParam reports whether a parameter name looks like an object identifier.
func IsIDParam(name string) bool {
	l := strings.ToLower(name)
	if IsTenantParam(l) {
		return false
	}
	for _, h := range idParamHints {
		if l == h || strings.HasSuffix(l, "_"+h) || strings.HasSuffix(l, h) || strings.HasPrefix(l, h+"_") {
			return true
		}
	}
	return false
}

// ShapeOf classifies an identifier value.
func ShapeOf(v string) Shape {
	switch {
	case v == "":
		return ShapeUnknown
	case endpoints.LooksIdentifierLike(v) && isDigits(v):
		return ShapeNumeric
	case len(v) == 36 && strings.Count(v, "-") == 4:
		return ShapeUUID
	case len(v) >= 12 && isHex(v):
		return ShapeHex
	case endpoints.LooksIdentifierLike(v):
		return ShapeOpaque
	default:
		return ShapeUnknown
	}
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// GuessResource infers the resource type from the path segment preceding an
// identifier: /api/v1/orders/123 -> "order".
func GuessResource(pathBefore string) string {
	segs := strings.Split(strings.Trim(pathBefore, "/"), "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s := strings.ToLower(segs[i])
		if s == "" || s == "api" || isVersion(s) || endpoints.LooksIdentifierLike(s) {
			continue
		}
		return singular(s)
	}
	return "object"
}

func isVersion(s string) bool {
	if strings.HasPrefix(s, "v") && len(s) <= 4 && strings.ContainsAny(s, "1234567890") {
		return true
	}
	return false
}

func singular(s string) string {
	if len(s) > 3 && strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss") {
		return s[:len(s)-1]
	}
	return s
}

// ConfidenceFor scores how likely a candidate is authorization-sensitive.
func ConfidenceFor(paramName string, loc Location, shape Shape) float64 {
	c := 0.35
	if IsIDParam(paramName) {
		c += 0.35
	}
	switch loc {
	case LocPath:
		c += 0.15
	case LocQuery:
		c += 0.05
	case LocResponse:
		c += 0.05
	}
	switch shape {
	case ShapeNumeric, ShapeUUID:
		c += 0.1
	case ShapeHex, ShapeOpaque:
		c += 0.05
	}
	if c > 1 {
		c = 1
	}
	return c
}
