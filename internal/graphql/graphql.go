// Package graphql implements the GraphQL protocol adapter (Master Prompt
// §26): harvesting observed operations from HAR traffic, classifying
// query/mutation, and building bounded object-level test requests. Batching
// is never used for enumeration; mutations are validated separately and
// remain write-gated.
package graphql

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Operation is one observed GraphQL HTTP operation.
type Operation struct {
	Endpoint  string         `json:"endpoint"`
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
	Kind      string         `json:"kind"` // query | mutation
	Source    string         `json:"source"`
}

// IsGraphQLBody reports whether a POST payload looks like a GraphQL request
// (a JSON object carrying a string "query" field).
func IsGraphQLBody(payload string) bool {
	op, ok := Harvest("", payload, "")
	return ok && op.Query != ""
}

// Harvest parses one POST payload into an Operation. ok is false when the
// payload is not a GraphQL request (then the returned Operation is empty).
func Harvest(endpoint, payload, source string) (Operation, bool) {
	payload = strings.TrimSpace(payload)
	if !strings.HasPrefix(payload, "{") {
		return Operation{}, false
	}
	var doc struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		return Operation{}, false
	}
	if strings.TrimSpace(doc.Query) == "" {
		return Operation{}, false
	}
	return Operation{
		Endpoint:  endpoint,
		Query:     doc.Query,
		Variables: doc.Variables,
		Kind:      KindOf(doc.Query),
		Source:    source,
	}, true
}

// KindOf classifies an operation text as "mutation" or "query" (comments
// and whitespace before the first keyword are ignored).
func KindOf(query string) string {
	for _, line := range strings.Split(query, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"mutation", "query"} {
			if strings.HasPrefix(line, prefix) {
				return prefix
			}
		}
		if line != "" && !strings.HasPrefix(line, "#") {
			break
		}
	}
	return "query"
}

// SwapID returns a deep copy of the variables with oldID replaced by newID
// in every string value (bounded recursion; non-string scalars untouched).
func SwapID(vars map[string]any, oldID, newID string) map[string]any {
	if oldID == "" || newID == "" || vars == nil {
		return vars
	}
	out, _ := swapMap(vars, oldID, newID, 0).(map[string]any)
	return out
}

func swapMap(m map[string]any, oldID, newID string, depth int) any {
	if depth > 8 {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = swapValue(v, oldID, newID, depth)
	}
	return out
}

func swapValue(v any, oldID, newID string, depth int) any {
	switch t := v.(type) {
	case string:
		if t == oldID {
			return newID
		}
		return strings.ReplaceAll(t, oldID, newID)
	case map[string]any:
		return swapMap(t, oldID, newID, depth+1)
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = swapValue(item, oldID, newID, depth+1)
		}
		return out
	default:
		return v
	}
}

// RenderRequest builds the HTTP JSON payload for an operation.
func RenderRequest(op Operation) string {
	b, err := json.Marshal(struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables,omitempty"`
	}{Query: op.Query, Variables: op.Variables})
	if err != nil {
		return fmt.Sprintf(`{"query":%q}`, op.Query)
	}
	return string(b)
}
