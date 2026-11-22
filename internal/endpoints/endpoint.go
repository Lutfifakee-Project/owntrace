// Package endpoints defines the normalized HTTP endpoint model used across
// discovery, testing and reporting, plus stable identity and deduplication.
package endpoints

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// SourceKind identifies where an endpoint was discovered.
type SourceKind string

const (
	SourceURL      SourceKind = "url"
	SourceHAR      SourceKind = "har"
	SourceOpenAPI  SourceKind = "openapi"
	SourceSwagger  SourceKind = "swagger"
	SourceCrawl    SourceKind = "crawl"
	SourceConfig   SourceKind = "config"
	SourceWorkflow SourceKind = "workflow"
	SourceGraphQL  SourceKind = "graphql"
)

// SourceRef records provenance for an endpoint or object.
type SourceRef struct {
	Kind     SourceKind `json:"kind"`
	Location string     `json:"location,omitempty"` // file path, URL, HAR entry index...
	Detail   string     `json:"detail,omitempty"`
}

// Param is one named parameter of an endpoint.
type Param struct {
	Name     string `json:"name"`
	In       string `json:"in"` // path | query | header | cookie | body
	Required bool   `json:"required,omitempty"`
	Example  string `json:"example,omitempty"`
	Schema   string `json:"schema,omitempty"` // string | integer | uuid | boolean | ...
}

// BodySpec describes a request body template.
type BodySpec struct {
	ContentType string  `json:"content_type,omitempty"`
	Template    string  `json:"template,omitempty"` // JSON template; {{param}} placeholders allowed
	Fields      []Param `json:"fields,omitempty"`   // structured body fields (body location)
}

// AuthRequirement summarizes what authentication an endpoint appears to need.
type AuthRequirement string

const (
	AuthUnknown AuthRequirement = "unknown"
	AuthNone    AuthRequirement = "none"
	AuthBearer  AuthRequirement = "bearer"
	AuthCookie  AuthRequirement = "cookie"
	AuthHeader  AuthRequirement = "header"
	AuthBasic   AuthRequirement = "basic"
)

// Endpoint is the canonical endpoint record. Path may contain {placeholder}
// segments derived from observed URLs or OpenAPI templates; Samples holds the
// concrete URLs seen in traffic.
type Endpoint struct {
	ID         string          `json:"id"` // stable content hash
	Method     string          `json:"method"`
	Host       string          `json:"host"` // scheme://host[:port]
	Path       string          `json:"path"` // may contain {placeholders}
	Query      []Param         `json:"query,omitempty"`
	Headers    []Param         `json:"headers,omitempty"`
	Body       *BodySpec       `json:"body,omitempty"`
	Auth       AuthRequirement `json:"auth,omitempty"`
	Samples    []string        `json:"samples,omitempty"` // concrete observed URLs
	Sources    []SourceRef     `json:"sources"`
	Adminish   bool            `json:"adminish,omitempty"`   // looks like a privileged endpoint
	Collection bool            `json:"collection,omitempty"` // path addresses a collection, not an item
}

// Key is the deduplication key: method + host + normalized path + required
// query names. Optional query variations merge into one endpoint rather than
// creating duplicates.
func (e *Endpoint) Key() string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(e.Method))
	b.WriteByte(' ')
	b.WriteString(e.Host)
	b.WriteString(normalizePath(e.Path))
	req := make([]string, 0, len(e.Query))
	for _, q := range e.Query {
		if q.Required {
			req = append(req, q.Name)
		}
	}
	if len(req) > 0 {
		sort.Strings(req)
		b.WriteByte('?')
		b.WriteString(strings.Join(req, "&"))
	}
	return b.String()
}

// normalizePath replaces concrete identifier-looking segments with {} so that
// /orders/1001 and /orders/1002 collapse into one templated endpoint.
func normalizePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	out := make([]string, len(segs))
	for i, s := range segs {
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			out[i] = s
		} else if LooksIdentifierLike(s) {
			out[i] = "{}"
		} else {
			out[i] = s
		}
	}
	return "/" + strings.Join(nonEmpty(out), "/")
}

func nonEmpty(ss []string) []string {
	out := ss[:0]
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ComputeID assigns a stable content-derived identifier.
func (e *Endpoint) ComputeID() string {
	h := sha256.Sum256([]byte(e.Key()))
	return "ep_" + hex.EncodeToString(h[:])[:12]
}

// URL renders the concrete (or templated) URL for the endpoint.
func (e *Endpoint) URL() string {
	return strings.TrimSuffix(e.Host, "/") + "/" + strings.TrimLeft(e.Path, "/")
}

// FillURL renders the URL with concrete values for placeholders, using the
// provided values keyed by placeholder name and falling back to examples.
func (e *Endpoint) FillURL(values map[string]string) (string, []string, error) {
	segs := strings.Split(strings.TrimLeft(e.Path, "/"), "/")
	missing := []string{}
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			name := s[1 : len(s)-1]
			v, ok := values[name]
			if !ok {
				// look for an example among path params
				for _, q := range e.Query {
					if q.In == "path" && q.Name == name && q.Example != "" {
						v, ok = q.Example, true
						break
					}
				}
			}
			if !ok || v == "" {
				missing = append(missing, name)
				continue
			}
			segs[i] = url.PathEscape(v)
		}
	}
	if len(missing) > 0 {
		return "", missing, fmt.Errorf("missing path values for %v", missing)
	}
	return e.Host + "/" + strings.Join(segs, "/"), nil, nil
}

// PathParams returns placeholder names in path order.
func (e *Endpoint) PathParams() []string {
	var out []string
	for _, s := range strings.Split(e.Path, "/") {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			out = append(out, s[1:len(s)-1])
		}
	}
	return out
}

// AddSource appends a provenance reference if not already present.
func (e *Endpoint) AddSource(k SourceKind, loc, detail string) {
	for _, s := range e.Sources {
		if s.Kind == k && s.Location == loc && s.Detail == detail {
			return
		}
	}
	e.Sources = append(e.Sources, SourceRef{Kind: k, Location: loc, Detail: detail})
}

// prefixedIDRe matches short prefixed numeric IDs like "o-1001", "inv-2001",
// "f-9" — a letter prefix, optional alphanumerics, hyphen, digits.
var prefixedIDRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,6}-\d+$`)

// LooksIdentifierLike reports whether a path segment or value looks like an
// object identifier: numeric, UUID, hex ID, long opaque token, prefixed
// numeric ID. It deliberately does NOT treat every short word as an
// identifier.
func LooksIdentifierLike(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if isAllDigits(s) {
		return true
	}
	if isUUID(s) {
		return true
	}
	// Numeric with separators (1_000, 12-34? no: date-like excluded later)
	if isNumericish(s) {
		return true
	}
	if prefixedIDRe.MatchString(s) {
		return true
	}
	// Pure hex of meaningful length (git-style SHA, mongo id)
	if len(s) >= 12 && isAllHex(s) {
		return true
	}
	// Base64-ish opaque token (e.g. dGVhbS0x..., tok-oPaQue-9f2xyz) of
	// meaningful length. Values starting with a digit are excluded: they are
	// usually dates or version strings (2024-annual-report), not IDs.
	if len(s) >= 16 && s[0] > '9' && isBase64ish(s) {
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isNumericish(s string) bool {
	digits := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return digits > 0
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHexDigit(byte(r)) {
				return false
			}
		}
	}
	return true
}

func isAllHex(s string) bool {
	for _, r := range s {
		if !isHexDigit(byte(r)) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isBase64ish(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-', r == '+', r == '/':
		default:
			return false
		}
	}
	// Must contain at least one digit-ish variety to avoid matching normal words
	hasUpper, hasLower, hasDigit := false, false, false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return (hasUpper && hasLower) || hasDigit
}

// PathParamName guesses the placeholder name for an identifier segment based
// on the preceding resource segment, e.g. /orders/1001 -> {order_id}.
func PathParamName(resourceSeg, rawID string) string {
	res := singularize(strings.ToLower(strings.TrimSpace(resourceSeg)))
	if res == "" {
		return "id"
	}
	if LooksIdentifierLike(rawID) && isUUID(rawID) {
		return res + "_uuid"
	}
	return res + "_id"
}

// singularize strips a trailing plural 's' from resource names (orders->order).
func singularize(s string) string {
	if len(s) > 3 && strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss") {
		return s[:len(s)-1]
	}
	return s
}

// Set is a deduplicating, thread-unsafe (single-pipeline) endpoint collection.
type Set struct {
	byKey map[string]*Endpoint
	order []string
}

func NewSet() *Set { return &Set{byKey: map[string]*Endpoint{}} }

// Add merges the endpoint into the set, deduplicating by Key and uniting
// parameters and samples. Returns the stored endpoint and whether it is new.
func (s *Set) Add(e *Endpoint) (*Endpoint, bool) {
	if e.Method == "" {
		e.Method = "GET"
	}
	e.Method = strings.ToUpper(e.Method)
	e.Host = strings.TrimSuffix(e.Host, "/")
	e.Path = "/" + strings.TrimLeft(e.Path, "/")
	key := e.Key()
	if existing, ok := s.byKey[key]; ok {
		mergeEndpoint(existing, e)
		return existing, false
	}
	if e.ID == "" {
		e.ID = e.ComputeID()
	}
	s.byKey[key] = e
	s.order = append(s.order, key)
	return e, true
}

func mergeEndpoint(dst, src *Endpoint) {
	dst.Query = mergeParams(dst.Query, src.Query)
	dst.Headers = mergeParams(dst.Headers, src.Headers)
	if src.Body != nil {
		if dst.Body == nil {
			dst.Body = src.Body
		} else {
			if dst.Body.ContentType == "" {
				dst.Body.ContentType = src.Body.ContentType
			}
			if dst.Body.Template == "" {
				dst.Body.Template = src.Body.Template
			}
			dst.Body.Fields = mergeParams(dst.Body.Fields, src.Body.Fields)
		}
	}
	if src.Auth != AuthUnknown && dst.Auth == AuthUnknown {
		dst.Auth = src.Auth
	}
	if src.Adminish {
		dst.Adminish = true
	}
	if src.Collection {
		dst.Collection = true
	}
	for _, smp := range src.Samples {
		if !containsString(dst.Samples, smp) {
			dst.Samples = append(dst.Samples, smp)
		}
	}
	for _, sr := range src.Sources {
		found := false
		for _, d := range dst.Sources {
			if d.Kind == sr.Kind && d.Location == sr.Location && d.Detail == sr.Detail {
				found = true
				break
			}
		}
		if !found {
			dst.Sources = append(dst.Sources, sr)
		}
	}
	// Keep normalized path with placeholders if either side had one.
	if hasPlaceholder(src.Path) && !hasPlaceholder(dst.Path) {
		dst.Path = src.Path
	}
}

func hasPlaceholder(p string) bool { return strings.Contains(p, "{") }

func mergeParams(a, b []Param) []Param {
	for _, p := range b {
		found := false
		for i := range a {
			if a[i].In == p.In && a[i].Name == p.Name {
				found = true
				if a[i].Example == "" && p.Example != "" {
					a[i].Example = p.Example
				}
				if a[i].Schema == "" && p.Schema != "" {
					a[i].Schema = p.Schema
				}
				a[i].Required = a[i].Required || p.Required
				break
			}
		}
		if !found {
			a = append(a, p)
		}
	}
	return a
}

func containsString(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// List returns endpoints in insertion order.
func (s *Set) List() []*Endpoint {
	out := make([]*Endpoint, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.byKey[k])
	}
	return out
}

// LookupByID finds an endpoint by its computed ID.
func (s *Set) LookupByID(id string) (*Endpoint, bool) {
	for _, ep := range s.byKey {
		if ep.ID == id {
			return ep, true
		}
	}
	return nil, false
}

// Len returns the number of unique endpoints.
func (s *Set) Len() int { return len(s.order) }
