// OpenAPI 3.x and Swagger 2.x parsing. The parser resolves local $refs,
// builds parameter lists, synthesizes request-body templates, maps security
// schemes to authentication requirements and records provenance. Malformed
// documents yield clear errors; individual broken paths are skipped with
// notes rather than failing the whole import.
package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
)

// ParseOpenAPI parses an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML).
func ParseOpenAPI(path string, res *Result) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read spec %s: %w", path, err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse spec %s: %w (JSON OpenAPI/Swagger expected)", path, err)
	}
	kind := endpoints.SourceOpenAPI
	if v, ok := root["swagger"]; ok {
		if s, _ := v.(string); strings.HasPrefix(s, "2.") {
			kind = endpoints.SourceSwagger
		}
	} else if v, ok := root["openapi"]; ok {
		if s, _ := v.(string); !strings.HasPrefix(s, "3.") {
			res.Note("%s: OpenAPI version %v untested; parsing as 3.x", path, v)
		}
	} else {
		return fmt.Errorf("%s: neither 'openapi' nor 'swagger' version field found", path)
	}

	paths, _ := root["paths"].(map[string]any)
	if len(paths) == 0 {
		res.Note("%s: no paths defined", path)
		return nil
	}

	bases := specBaseURLs(root, kind)
	globalSecurity := securityNames(root["security"])

	pathNames := make([]string, 0, len(paths))
	for p := range paths {
		pathNames = append(pathNames, p)
	}
	sort.Strings(pathNames)

	for _, p := range pathNames {
		pathItem, _ := paths[p].(map[string]any)
		if pathItem == nil {
			continue
		}
		for _, method := range httpMethods {
			op, _ := pathItem[method].(map[string]any)
			if op == nil {
				continue
			}
			for _, ep := range buildOperationEndpoints(kind, path, strings.ToUpper(method), p, op, pathItem, root, bases, globalSecurity) {
				res.Endpoints.Add(ep)
			}
		}
	}
	return nil
}

var httpMethods = []string{"get", "post", "put", "patch", "delete", "head", "options", "trace"}

func specBaseURLs(root map[string]any, kind endpoints.SourceKind) []string {
	var bases []string
	if kind == endpoints.SourceOpenAPI {
		servers, _ := root["servers"].([]any)
		for _, s := range servers {
			m, _ := s.(map[string]any)
			if m == nil {
				continue
			}
			if u, ok := m["url"].(string); ok && u != "" {
				bases = append(bases, strings.TrimSuffix(u, "/"))
			}
		}
	} else {
		host, _ := root["host"].(string)
		basePath, _ := root["basePath"].(string)
		schemes, _ := root["schemes"].([]any)
		if host != "" {
			schList := []string{"https"}
			if len(schemes) > 0 {
				schList = nil
				for _, s := range schemes {
					if str, _ := s.(string); str != "" {
						schList = append(schList, str)
					}
				}
			}
			for _, sch := range schList {
				bases = append(bases, sch+"://"+host+strings.TrimSuffix(basePath, "/"))
			}
		}
	}
	if len(bases) == 0 {
		bases = []string{""} // relative; orchestrator must resolve against seeds
	}
	return bases
}

// resolveRef walks local $refs (#/components/... or #/definitions/...).
func resolveRef(node any, root map[string]any) map[string]any {
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	ref, _ := m["$ref"].(string)
	if ref == "" || !strings.HasPrefix(ref, "#/") {
		return m
	}
	cur := any(root)
	for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		seg = strings.ReplaceAll(seg, "~1", "/")
		seg = strings.ReplaceAll(seg, "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			cur = t[seg]
		case []any:
			idx := -1
			for i, c := 0, 0; i < len(seg); i++ {
				if seg[i] < '0' || seg[i] > '9' {
					idx = -1
					break
				}
				idx = c*10 + int(seg[i]-'0')
				c = idx
			}
			if idx < 0 || idx >= len(t) {
				return m
			}
			cur = t[idx]
		default:
			return m
		}
	}
	if mm, ok := cur.(map[string]any); ok {
		return mm
	}
	return m
}

func parameterList(node any, root map[string]any) []endpoints.Param {
	rawList, _ := node.([]any)
	var out []endpoints.Param
	for _, item := range rawList {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		m = resolveRef(m, root)
		p := paramFromMap(m, root)
		if p != nil {
			out = append(out, *p)
		}
	}
	return out
}

func paramFromMap(m map[string]any, root map[string]any) *endpoints.Param {
	name, _ := m["name"].(string)
	in, _ := m["in"].(string)
	if name == "" || in == "" {
		return nil
	}
	p := endpoints.Param{Name: name, In: in}
	if req, ok := m["required"].(bool); ok {
		p.Required = req
	}
	if in == "path" {
		p.Required = true
	}
	schema := resolveRef(m["schema"], root)
	if schema == nil {
		schema = m // Swagger 2.0 puts type/example inline
	}
	p.Schema = schemaType(schema)
	if ex := exampleValue(schema, name); ex != "" {
		p.Example = ex
	}
	return &p
}

func schemaType(schema map[string]any) string {
	if schema == nil {
		return ""
	}
	t, _ := schema["type"].(string)
	if t == "" {
		if _, ok := schema["properties"]; ok {
			return "object"
		}
		if _, ok := schema["items"]; ok {
			return "array"
		}
	}
	if f, ok := schema["format"].(string); ok && t == "string" && (f == "uuid" || f == "email") {
		return f
	}
	return t
}

func exampleValue(schema map[string]any, name string) string {
	if schema == nil {
		return ""
	}
	if ex, ok := schema["example"]; ok {
		if s, ok := ex.(string); ok {
			return s
		}
	}
	if df, ok := schema["default"]; ok {
		if s, ok := df.(string); ok {
			return s
		}
	}
	// Sensible synthetic examples by format.
	switch schemaType(schema) {
	case "uuid":
		return "00000000-0000-4000-8000-000000000000"
	case "email":
		return "user@example.com"
	}
	if t := schemaType(schema); t == "integer" || t == "number" {
		return "1"
	}
	return ""
}

func securityNames(node any) []string {
	arr, _ := node.([]any)
	var out []string
	for _, item := range arr {
		m, _ := item.(map[string]any)
		for k := range m {
			out = append(out, k)
		}
	}
	return out
}

func buildOperationEndpoints(kind endpoints.SourceKind, pathTmpl, method, loc string, op, pathItem map[string]any,
	root map[string]any, bases []string, globalSecurity []string) []*endpoints.Endpoint {

	if op["$ref"] != nil {
		ref := resolveRef(op, root)
		if ref == nil {
			return nil
		}
		op = ref
	}
	ep := &endpoints.Endpoint{Method: method, Path: pathTmpl, Auth: endpoints.AuthUnknown}
	ep.AddSource(kind, loc, opID(op))

	// parameters: path-level + operation-level
	params := parameterList(pathItem["parameters"], root)
	params = append(params, parameterList(op["parameters"], root)...)
	for _, p := range params {
		switch p.In {
		case "path":
			ep.Query = append(ep.Query, p)
		case "query":
			ep.Query = append(ep.Query, p)
		case "header":
			ep.Headers = append(ep.Headers, p)
		case "cookie":
			ep.Auth = endpoints.AuthCookie
		}
	}

	// request body
	body := buildBodySpec(op, root)
	if body != nil {
		ep.Body = body
	}

	// security requirement
	secNames := securityNames(op["security"])
	if len(secNames) == 0 {
		secNames = globalSecurity
	}
	ep.Auth = authFromSecurity(root, secNames)
	if ep.Auth == endpoints.AuthUnknown {
		// heuristic: Authorization/Cookie header params imply auth
		for _, h := range ep.Headers {
			if strings.EqualFold(h.Name, "Authorization") {
				ep.Auth = endpoints.AuthBearer
			}
		}
	}

	lower := strings.ToLower(pathTmpl)
	if strings.Contains(lower, "admin") || strings.Contains(lower, "internal") {
		ep.Adminish = true
	}
	ep.Collection = !strings.Contains(pathTmpl, "{")

	if len(bases) == 1 && bases[0] == "" {
		// Relative-only spec: no concrete base to test against.
		return nil
	}
	var out []*endpoints.Endpoint
	for _, b := range bases {
		e2 := *ep
		e2.Host = b
		e2.Samples = append(e2.Samples, b+pathTmpl)
		out = append(out, &e2)
	}
	return out
}

func opID(op map[string]any) string {
	if v, ok := op["operationId"].(string); ok {
		return v
	}
	if v, ok := op["summary"].(string); ok {
		return v
	}
	return ""
}

func buildBodySpec(op map[string]any, root map[string]any) *endpoints.BodySpec {
	// OpenAPI 3: requestBody
	if rb := resolveRef(op["requestBody"], root); rb != nil {
		content, _ := rb["content"].(map[string]any)
		if bs := bodyFromContent(content, root); bs != nil {
			return bs
		}
	}
	// Swagger 2: body parameter or formData
	params := parameterList(op["parameters"], root)
	for _, p := range params {
		if p.In == "body" {
			return &endpoints.BodySpec{ContentType: "application/json", Template: "{{body}}"}
		}
	}
	return nil
}

func bodyFromContent(content map[string]any, root map[string]any) *endpoints.BodySpec {
	if content == nil {
		return nil
	}
	order := []string{"application/json", "application/x-www-form-urlencoded"}
	for _, ct := range order {
		media, ok := content[ct].(map[string]any)
		if !ok {
			continue
		}
		bs := &endpoints.BodySpec{ContentType: ct}
		if ex, ok := media["example"]; ok {
			if b, err := json.Marshal(ex); err == nil {
				bs.Template = string(b)
			}
		}
		if bs.Template == "" {
			schema := resolveRef(media["schema"], root)
			if schema != nil {
				bs.Template = synthFromSchema(schema, root, 0)
			}
		}
		if bs.Template == "" && ct == "application/json" {
			bs.Template = "{}"
		}
		return bs
	}
	// fall back to first content type
	for ct, media := range content {
		m, _ := media.(map[string]any)
		if m == nil {
			continue
		}
		bs := &endpoints.BodySpec{ContentType: ct}
		if schema := resolveRef(m["schema"], root); schema != nil {
			bs.Template = synthFromSchema(schema, root, 0)
		}
		return bs
	}
	return nil
}

// synthFromSchema generates a minimal JSON template from a schema. String
// placeholders use {{field}} markers filled during testing.
func synthFromSchema(schema map[string]any, root map[string]any, depth int) string {
	if depth > 6 {
		return "null"
	}
	schema = resolveRef(schema, root)
	t := schemaType(schema)
	switch t {
	case "object":
		props, _ := schema["properties"].(map[string]any)
		if len(props) == 0 {
			return "{}"
		}
		names := make([]string, 0, len(props))
		for n := range props {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		b.WriteString("{")
		for i, n := range names {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("\"" + n + "\":" + synthFromSchema(props[n].(map[string]any), root, depth+1))
		}
		b.WriteString("}")
		return b.String()
	case "array":
		items := resolveRef(schema["items"], root)
		return "[" + synthFromSchema(items, root, depth+1) + "]"
	case "string":
		return "\"{{" + t + "}}\""
	case "integer", "number":
		return "0"
	case "boolean":
		return "false"
	default:
		return "null"
	}
}

func authFromSecurity(root map[string]any, secNames []string) endpoints.AuthRequirement {
	if len(secNames) == 0 {
		return endpoints.AuthUnknown
	}
	comps, _ := root["components"].(map[string]any)
	schemes, _ := comps["securitySchemes"].(map[string]any)
	if schemes == nil {
		schemes, _ = root["securityDefinitions"].(map[string]any)
	}
	for _, name := range secNames {
		var sch map[string]any
		if schemes != nil {
			sch, _ = schemes[name].(map[string]any)
		}
		if sch == nil {
			return endpoints.AuthUnknown
		}
		typ, _ := sch["type"].(string)
		switch typ {
		case "http":
			s, _ := sch["scheme"].(string)
			switch s {
			case "bearer":
				return endpoints.AuthBearer
			case "basic":
				return endpoints.AuthBasic
			}
		case "apiKey":
			in, _ := sch["in"].(string)
			if in == "header" {
				return endpoints.AuthHeader
			}
			if in == "cookie" {
				return endpoints.AuthCookie
			}
			return endpoints.AuthHeader
		case "oauth2", "openIdConnect":
			return endpoints.AuthBearer
		}
	}
	return endpoints.AuthUnknown
}
