// Concrete-URL → Endpoint construction (templating identifier segments).
package endpoints

import (
	"net/url"
	"strings"
)

// BuildFromURL creates an endpoint from a concrete URL. Identifier-looking
// path segments become placeholders; the resource segment before them names
// the placeholder.
func BuildFromURL(method, raw string, srcKind SourceKind, srcLoc string) (*Endpoint, bool) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	host, p, qs, ok := splitURL(raw)
	if !ok {
		return nil, false
	}
	ep := &Endpoint{Method: method, Host: host, Path: p}
	ep.Sources = append(ep.Sources, SourceRef{Kind: srcKind, Location: srcLoc})
	ep.Samples = append(ep.Samples, raw)

	segs := strings.Split(strings.Trim(p, "/"), "/")
	out := make([]string, len(segs))
	for i, s := range segs {
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			out[i] = s // already templated (OpenAPI)
			continue
		}
		if LooksIdentifierLike(s) {
			prev := ""
			for j := i - 1; j >= 0; j-- {
				if segs[j] != "" {
					prev = segs[j]
					break
				}
			}
			name := PathParamName(prev, s)
			out[i] = "{" + name + "}"
			ep.Query = append(ep.Query, Param{Name: name, In: "path", Required: true, Example: s})
		} else {
			out[i] = s
		}
	}
	ep.Path = "/" + strings.Join(nonEmptyStr(out), "/")

	for _, q := range qs {
		for k, vs := range q {
			if len(vs) == 0 {
				continue
			}
			ep.Query = append(ep.Query, Param{Name: k, In: "query", Example: vs[0]})
		}
	}
	lower := strings.ToLower(p)
	if strings.Contains(lower, "admin") || strings.Contains(lower, "internal") {
		ep.Adminish = true
	}
	ep.Collection = !strings.Contains(ep.Path, "{")
	ep.Auth = AuthUnknown
	return ep, true
}

// splitURL splits a URL into host + path + query values.
func splitURL(raw string) (host, path string, query []url.Values, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", nil, false
	}
	var q []url.Values
	if u.RawQuery != "" {
		q = append(q, u.Query())
	}
	return u.Scheme + "://" + u.Host, u.Path, q, true
}

func nonEmptyStr(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
