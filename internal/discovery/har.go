// HAR 1.2 parsing for endpoint discovery and traffic-backed object mining.
// Malformed entries are skipped with notes; the parser never panics on bad
// input and never trusts capture contents.
package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/graphql"
)

// HAR structures (subset relevant to discovery).
type harFile struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name string `json:"name"`
		} `json:"creator"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	StartedDateTime string   `json:"startedDateTime"`
	Time            float64  `json:"time"`
	Request         harReq   `json:"request"`
	Response        harResp  `json:"response"`
	Cache           struct{} `json:"cache"`
}

type harKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harReq struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Headers     []harKV  `json:"headers"`
	QueryString []harKV  `json:"queryString"`
	Cookies     []harKV  `json:"cookies"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
	PostData    *harPost `json:"postData,omitempty"`
	Comment     string   `json:"comment,omitempty"`
}

type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Params   []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"params,omitempty"`
}

type harResp struct {
	Status     int     `json:"status"`
	StatusText string  `json:"statusText"`
	Headers    []harKV `json:"headers"`
	Content    struct {
		Size     int    `json:"size"`
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
		Encoding string `json:"encoding,omitempty"`
	} `json:"content"`
}

// ParseHAR parses a HAR file into endpoints and response samples. Profile
// attribution uses the configured capture header (default X-Owntrace-Profile).
// Scope filtering happens in the orchestrator; this layer is pure parsing.
func ParseHAR(path string, profileHeader string, res *Result) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read HAR %s: %w", path, err)
	}
	var hf harFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&hf); err != nil {
		return fmt.Errorf("parse HAR %s: %w (is it valid HAR 1.2 JSON?)", path, err)
	}
	if len(hf.Log.Entries) == 0 {
		res.Note("HAR %s contains no entries", path)
		return nil
	}
	if profileHeader == "" {
		profileHeader = "X-Owntrace-Profile"
	}
	for i, e := range hf.Log.Entries {
		loc := fmt.Sprintf("%s#%d", path, i)
		if e.Request.URL == "" || e.Request.Method == "" {
			res.Note("HAR entry %s skipped: missing method or URL", loc)
			continue
		}
		ep, ok := BuildFromURL(e.Request.Method, e.Request.URL, endpoints.SourceHAR, loc)
		if !ok {
			res.Note("HAR entry %s skipped: unparseable URL", loc)
			continue
		}
		profile := ""
		for _, h := range e.Request.Headers {
			if strings.EqualFold(h.Name, profileHeader) {
				profile = strings.TrimSpace(h.Value)
			}
			if strings.EqualFold(h.Name, "Authorization") && ep.Auth == endpoints.AuthUnknown {
				ep.Auth = endpoints.AuthBearer
			}
			if strings.EqualFold(h.Name, "Cookie") && ep.Auth == endpoints.AuthUnknown {
				ep.Auth = endpoints.AuthCookie
			}
		}
		if e.Request.PostData != nil && e.Request.PostData.Text != "" {
			ep.Body = &endpoints.BodySpec{
				ContentType: e.Request.PostData.MimeType,
				Template:    e.Request.PostData.Text,
			}
			if strings.Contains(strings.ToLower(e.Request.PostData.MimeType), "json") {
				for _, f := range jsonBodyFields([]byte(e.Request.PostData.Text), "") {
					ep.Body.Fields = append(ep.Body.Fields, endpoints.Param{Name: f.path, In: "body", Example: f.val})
				}
				// GraphQL adapter (§26): harvest observed operations.
				if op, ok := graphql.Harvest(e.Request.URL, e.Request.PostData.Text, loc); ok {
					res.GraphQLOps = append(res.GraphQLOps, op)
				}
			}
		}
		stored, _ := res.Endpoints.Add(ep)
		if e.Response.Status > 0 && e.Response.Content.Text != "" {
			body := e.Response.Content.Text
			if len(body) > 64<<10 {
				body = body[:64<<10] + "…[truncated]"
			}
			res.Samples = append(res.Samples, ResponseSample{
				EndpointKey: stored.Key(), URL: e.Request.URL, Method: e.Request.Method,
				Profile: profile, Status: e.Response.Status,
				ContentType: e.Response.Content.MimeType, Body: body,
			})
		}
	}
	return nil
}

// jsonField is one flattened JSON field path and its scalar value.
type jsonField struct {
	path string
	val  string
}

// jsonBodyFields flattens a JSON object into dot-path scalar fields, e.g.
// {"user":{"id":5}} -> user.id=5. Bounded depth for safety.
func jsonBodyFields(raw []byte, prefix string) []jsonField {
	var v any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	var out []jsonField
	var walk func(node any, path string, depth int)
	walk = func(node any, path string, depth int) {
		if depth > 8 || len(out) > 64 {
			return
		}
		switch t := node.(type) {
		case map[string]any:
			for k, val := range t {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(val, p, depth+1)
			}
		case []any:
			for i, val := range t {
				if i >= 8 {
					break
				}
				walk(val, path, depth+1)
			}
		case string:
			if len(t) <= 256 {
				out = append(out, jsonField{path: path, val: t})
			}
		case float64:
			out = append(out, jsonField{path: path, val: trimFloat(t)})
		case bool:
			if t {
				out = append(out, jsonField{path: path, val: "true"})
			} else {
				out = append(out, jsonField{path: path, val: "false"})
			}
		}
	}
	walk(v, prefix, 0)
	return out
}

func trimFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}
