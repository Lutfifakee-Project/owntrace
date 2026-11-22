// Object candidate extraction from endpoints, URLs and observed responses.
package objects

import (
	"sort"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/util"
)

// FromEndpoint derives candidates from an endpoint's own structure: path
// placeholders, id-like query params and id-like body fields.
func FromEndpoint(ep *endpoints.Endpoint) []*Candidate {
	var out []*Candidate
	add := func(name, example string, loc Location, conf float64) {
		c := &Candidate{
			EndpointID: ep.ID,
			Resource:   GuessResource(resourceBefore(ep.Path, name)),
			ParamName:  name,
			Location:   loc,
			Example:    example,
			Shape:      ShapeOf(example),
			Confidence: conf,
			Sources:    ep.Sources,
		}
		c.ID = c.Key()
		out = append(out, c)
	}

	// path placeholders
	for _, seg := range strings.Split(ep.Path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			name := seg[1 : len(seg)-1]
			example := exampleFor(ep, name)
			conf := ConfidenceFor(name, LocPath, ShapeOf(example))
			if IsTenantParam(name) {
				conf -= 0.25 // tenant selectors tested separately
			}
			add(name, example, LocPath, conf)
		}
	}
	// query params
	for _, q := range ep.Query {
		if q.In != "query" {
			continue
		}
		if IsIDParam(q.Name) {
			add(q.Name, q.Example, LocQuery, ConfidenceFor(q.Name, LocQuery, ShapeOf(q.Example)))
		}
	}
	// body fields
	if ep.Body != nil {
		for _, f := range ep.Body.Fields {
			if IsIDParam(f.Name) {
				add(f.Name, f.Example, LocBody, ConfidenceFor(f.Name, LocBody, ShapeOf(f.Example)))
			}
		}
	}
	return out
}

// resourceBefore finds the path segment before the placeholder with the
// given name, e.g. /orders/{order_id} -> /orders.
func resourceBefore(path, name string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if s == "{"+name+"}" && i > 0 {
			return strings.Join(segs[:i], "/")
		}
	}
	return path
}

func exampleFor(ep *endpoints.Endpoint, name string) string {
	for _, q := range ep.Query {
		if q.Name == name && q.Example != "" {
			return q.Example
		}
	}
	for _, h := range ep.Headers {
		if h.Name == name && h.Example != "" {
			return h.Example
		}
	}
	return ""
}

// FromResponse mines identifiers out of an observed response body. Field keys
// ending in id/uuid/_id are considered; values must look like identifiers.
// Generic collection listings (arrays of objects) are handled as well.
func FromResponse(endpointID string, body []byte, contentType string, sources []endpoints.SourceRef) []*Candidate {
	if !strings.Contains(strings.ToLower(contentType), "json") && !looksLikeJSON(body) {
		return nil
	}
	v := util.DecodeJSONLoose(body)
	if v == nil {
		return nil
	}
	var out []*Candidate
	seen := map[string]bool{}
	util.WalkStrings(v, func(path string, s string) {
		if len(s) > 128 || s == "" {
			return
		}
		field := lastSegment(path)
		if !IsIDParam(field) && !strings.HasSuffix(strings.ToLower(field), "id") {
			return
		}
		if !endpoints.LooksIdentifierLike(s) && ShapeOf(s) == ShapeUnknown {
			return
		}
		res := GuessResource(parentSegments(path))
		c := &Candidate{
			EndpointID: endpointID,
			Resource:   res,
			ParamName:  field,
			Location:   LocResponse,
			Example:    s,
			Shape:      ShapeOf(s),
			Confidence: ConfidenceFor(field, LocResponse, ShapeOf(s)),
			Sources:    sources,
		}
		c.ID = c.Key() + "|" + s
		if !seen[c.ID] {
			seen[c.ID] = true
			out = append(out, c)
		}
	})
	if len(out) > 32 {
		sort.Slice(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
		out = out[:32]
	}
	return out
}

func lastSegment(path string) string {
	parts := strings.Split(path, ".")
	return parts[len(parts)-1]
}

func parentSegments(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) <= 1 {
		return ""
	}
	return strings.Join(parts[:len(parts)-1], ".")
}

func looksLikeJSON(body []byte) bool {
	t := strings.TrimSpace(string(body))
	if t == "" {
		return false
	}
	return (t[0] == '{' || t[0] == '[')
}
