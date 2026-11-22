// Limited, scope-bound HTML/JS crawling. The crawler only issues GET requests
// inside the configured scope, honors depth and page budgets, and extracts
// links, forms and JS-embedded API routes.
package discovery

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// jsRouteRe matches string-literal API-ish paths in JavaScript bundles.
var jsRouteRe = regexp.MustCompile(`["'` + "`" + `](/(?:api|v[0-9]+|rest)/[A-Za-z0-9_\-./{}$:]*)["'` + "`" + `]`)

// Crawl walks seed pages, collecting endpoints. GET-only, depth/page bounded.
func Crawl(ctx context.Context, client *httpclient.Client, sc *scope.Checker, seeds []string,
	maxDepth, maxPages int, log *logger.Logger, res *Result) {

	type page struct {
		url   string
		depth int
	}
	visited := map[string]bool{}
	queue := []page{}
	for _, s := range seeds {
		queue = append(queue, page{url: s, depth: 0})
	}
	pages := 0
	for len(queue) > 0 && pages < maxPages {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur.url] {
			continue
		}
		visited[cur.url] = true
		if d := sc.Check("GET", cur.url); !d.Allowed {
			log.Debugf("crawl skip out-of-scope %s: %s", cur.url, d.Reason)
			continue
		}
		pages++
		x := client.Do(ctx, "GET", cur.url, httpclient.Options{})
		if !x.Succeeded() || !x.Is2xx() {
			log.Debugf("crawl fetch failed %s: status=%d err=%s", cur.url, x.Status, x.Err)
			continue
		}
		ctype := strings.ToLower(x.ContentType)
		if !strings.Contains(ctype, "html") && !strings.Contains(ctype, "javascript") && !strings.Contains(ctype, "text/plain") {
			continue
		}
		body := x.Body
		ep, ok := BuildFromURL("GET", cur.url, endpoints.SourceCrawl, "crawl")
		if ok {
			res.Endpoints.Add(ep)
		}
		// links
		for _, href := range extractHrefs(body) {
			abs := resolveAgainst(cur.url, href)
			if abs == "" {
				continue
			}
			if d := sc.Check("GET", abs); !d.Allowed {
				continue
			}
			if newEp, ok := BuildFromURL("GET", abs, endpoints.SourceCrawl, "crawl:"+strconv.Itoa(cur.depth)); ok {
				res.Endpoints.Add(newEp)
			}
			if cur.depth < maxDepth && !visited[abs] {
				queue = append(queue, page{url: abs, depth: cur.depth + 1})
			}
		}
		// forms
		for _, f := range extractForms(body) {
			abs := resolveAgainst(cur.url, f.action)
			if abs == "" {
				continue
			}
			method := strings.ToUpper(orDefault(f.method, "GET"))
			if d := sc.Check(method, abs); !d.Allowed {
				continue
			}
			fe, ok := BuildFromURL(method, abs, endpoints.SourceCrawl, "crawl:form")
			if !ok {
				continue
			}
			if method != "GET" {
				fe.Body = &endpoints.BodySpec{ContentType: "application/x-www-form-urlencoded", Template: f.fields}
			}
			res.Endpoints.Add(fe)
		}
		// JS-embedded routes
		for _, m := range jsRouteRe.FindAllStringSubmatch(body, 32) {
			route := m[1]
			route = strings.TrimSuffix(route, "/")
			abs := resolveAgainst(cur.url, route)
			if abs == "" {
				continue
			}
			if d := sc.Check("GET", abs); !d.Allowed {
				continue
			}
			if newEp, ok := BuildFromURL("GET", abs, endpoints.SourceCrawl, "crawl:js"); ok {
				res.Endpoints.Add(newEp)
			}
		}
	}
	if pages >= maxPages {
		res.Note("crawl stopped at page budget (%d pages)", maxPages)
	}
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// extractHrefs pulls anchor hrefs from HTML (regex-based, tolerant).
func extractHrefs(body string) []string {
	re := regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["']([^"'#]+)["']`)
	var out []string
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(body, 128) {
		h := strings.TrimSpace(m[1])
		if h == "" || strings.HasPrefix(h, "javascript:") || strings.HasPrefix(h, "mailto:") || strings.HasPrefix(h, "tel:") {
			continue
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

type formInfo struct {
	action string
	method string
	fields string
}

// extractForms finds <form> blocks and their input names.
func extractForms(body string) []formInfo {
	formRe := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	actionRe := regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
	methodRe := regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
	inputRe := regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*["']([^"']+)["']`)
	var out []formInfo
	for _, m := range formRe.FindAllStringSubmatch(body, 16) {
		block := m[0]
		fi := formInfo{}
		if am := actionRe.FindStringSubmatch(block); am != nil {
			fi.action = am[1]
		}
		if mm := methodRe.FindStringSubmatch(block); mm != nil {
			fi.method = mm[1]
		}
		var names []string
		for _, im := range inputRe.FindAllStringSubmatch(block, 32) {
			names = append(names, im[1]+"={{"+im[1]+"}}")
		}
		fi.fields = strings.Join(names, "&")
		out = append(out, fi)
	}
	return out
}

// resolveAgainst resolves a possibly-relative URL against a base.
func resolveAgainst(base, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if !strings.HasPrefix(ref, "/") {
		return "" // relative paths without slash are ambiguous; skip
	}
	// find scheme://host prefix
	schemeEnd := strings.Index(base, "://")
	if schemeEnd < 0 {
		return ""
	}
	hostPart := base[:schemeEnd+3]
	rest := base[schemeEnd+3:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		hostPart += rest[:slash]
	}
	return hostPart + ref
}
