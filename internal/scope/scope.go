// Package scope implements deny-by-default target scope enforcement.
//
// Rules:
//   - Only explicitly configured hosts may receive requests.
//   - Path prefixes must match include_paths and not match exclude_paths.
//   - HTTP methods must be allowed globally and by the matching target.
//   - Redirects are validated hop-by-hop: the final destination (and every
//     intermediate hop) must remain in scope or the request is aborted.
//   - Subdomains are NOT automatically in scope (configurable opt-in).
package scope

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
)

// Decision explains a scope verdict.
type Decision struct {
	Allowed bool
	Reason  string
}

func allow(msg string) Decision { return Decision{Allowed: true, Reason: msg} }
func deny(msg string) Decision  { return Decision{Allowed: false, Reason: msg} }

// blockedScheme / special hosts that must never be contacted regardless of
// configuration, to rule out trivial SSRF-into-infrastructure mistakes.
var blockedSchemes = map[string]bool{"file": true, "gopher": true, "ftp": true, "data": true}

type compiledTarget struct {
	host         string
	schemes      map[string]bool
	includes     []*regexp.Regexp
	excludes     []*regexp.Regexp
	methods      map[string]bool
	maxRequests  int64
	requestCount int64
}

// Checker validates requests against the configured scope.
type Checker struct {
	targets       []*compiledTarget
	globalMethods map[string]bool
	blockedPaths  []*regexp.Regexp
	allowSubdoms  bool
	maxTotal      int64
	totalCount    int64
}

// New compiles the scope configuration. Returns an error on invalid patterns
// so misconfiguration fails fast before any request is sent.
func New(cfg config.Scope) (*Checker, error) {
	c := &Checker{
		allowSubdoms:  cfg.AllowSubdomains,
		globalMethods: map[string]bool{},
	}
	if cfg.MaxRequestsTotal > 0 {
		c.maxTotal = int64(cfg.MaxRequestsTotal)
	}
	for _, m := range cfg.GlobalAllowedMethods {
		c.globalMethods[strings.ToUpper(m)] = true
	}
	for _, pat := range cfg.BlockedPathPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("scope.blocked_path_patterns: invalid regex %q: %w", pat, err)
		}
		c.blockedPaths = append(c.blockedPaths, re)
	}
	for i, t := range cfg.Targets {
		ct := &compiledTarget{
			host:        strings.ToLower(strings.TrimSpace(t.Host)),
			schemes:     map[string]bool{},
			methods:     map[string]bool{},
			maxRequests: int64(t.MaxRequests),
		}
		for _, s := range t.Schemes {
			ct.schemes[strings.ToLower(s)] = true
		}
		if len(ct.schemes) == 0 {
			ct.schemes["http"] = true
			ct.schemes["https"] = true
		}
		if len(t.AllowedMethods) > 0 {
			for _, m := range t.AllowedMethods {
				ct.methods[strings.ToUpper(m)] = true
			}
		} else {
			for m := range c.globalMethods {
				ct.methods[m] = true
			}
		}
		for _, p := range t.IncludePaths {
			re, err := pathPrefixRe(p)
			if err != nil {
				return nil, fmt.Errorf("scope.targets[%d] include_paths: %w", i, err)
			}
			ct.includes = append(ct.includes, re)
		}
		for _, p := range t.ExcludePaths {
			re, err := pathPrefixRe(p)
			if err != nil {
				return nil, fmt.Errorf("scope.targets[%d] exclude_paths: %w", i, err)
			}
			ct.excludes = append(ct.excludes, re)
		}
		c.targets = append(c.targets, ct)
	}
	return c, nil
}

// pathPrefixRe compiles an include/exclude path expression. A plain prefix
// like /api matches /api and anything under it; a pattern containing regex
// metacharacters is treated as a regex anchored to the start of the path.
func pathPrefixRe(p string) (*regexp.Regexp, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return regexp.MustCompile(`^/`), nil
	}
	trimmed := strings.TrimSuffix(p, "*")
	quoted := regexp.QuoteMeta(strings.TrimSuffix(trimmed, "/"))
	return regexp.Compile(`^` + quoted + `(/|$|\?)`)
}

// hostMatches compares request host with target host honoring the subdomain
// policy. Ports must match exactly.
func hostMatches(reqHost, targetHost string, allowSubdomains bool) bool {
	reqHost, targetHost = strings.ToLower(reqHost), strings.ToLower(targetHost)
	if reqHost == targetHost {
		return true
	}
	if allowSubdomains && strings.HasSuffix(reqHost, "."+targetHost) {
		return true
	}
	return false
}

// findTarget returns the compiled target matching the host, or nil.
func (c *Checker) findTarget(host string) *compiledTarget {
	for _, t := range c.targets {
		if hostMatches(host, t.host, c.allowSubdoms) {
			return t
		}
	}
	return nil
}

// CheckURL validates scheme://host/path without method constraints. Used by
// redirect validation and discovery filters.
func (c *Checker) CheckURL(raw string) Decision {
	u, err := url.Parse(raw)
	if err != nil {
		return deny("unparseable URL: " + err.Error())
	}
	if blockedSchemes[u.Scheme] {
		return deny("scheme not permitted: " + u.Scheme)
	}
	if u.User != nil {
		return deny("URLs with embedded credentials are refused")
	}
	if u.Hostname() == "" {
		return deny("URL has no host")
	}
	t := c.findTarget(u.Host)
	if t == nil {
		if c.allowSubdoms {
			return deny(fmt.Sprintf("host %q is not in the configured scope", u.Host))
		}
		return deny(fmt.Sprintf("host %q is not in the configured scope (subdomains are not auto-authorized)", u.Host))
	}
	if len(t.schemes) > 0 && !t.schemes[strings.ToLower(u.Scheme)] {
		return deny(fmt.Sprintf("scheme %q not allowed for target %s", u.Scheme, t.host))
	}
	p := path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	for _, re := range t.excludes {
		if re.MatchString(p) {
			return deny(fmt.Sprintf("path %s matches exclude pattern", p))
		}
	}
	if len(t.includes) > 0 {
		matched := false
		for _, re := range t.includes {
			if re.MatchString(p) {
				matched = true
				break
			}
		}
		if !matched {
			return deny(fmt.Sprintf("path %s outside include patterns of target %s", p, t.host))
		}
	}
	return allow("in scope")
}

// Check validates a concrete request (method + URL + path context) against
// the full rule set including method and destructive-path guards.
func (c *Checker) Check(method, raw string) Decision {
	method = strings.ToUpper(method)
	if !c.globalMethods[method] && !c.targetAllowsMethod(method, raw) {
		// method must be allowed globally OR by the matched target
		if d := c.CheckURL(raw); !d.Allowed {
			return d
		}
		return deny(fmt.Sprintf("method %s not permitted by scope configuration", method))
	}
	d := c.CheckURL(raw)
	if !d.Allowed {
		return d
	}
	u, _ := url.Parse(raw)
	for _, re := range c.blockedPaths {
		if re.MatchString(u.Path) {
			return deny(fmt.Sprintf("path %s matches blocked (destructive) pattern %s", u.Path, re.String()))
		}
	}
	return allow("in scope")
}

func (c *Checker) targetAllowsMethod(method, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	t := c.findTarget(u.Host)
	return t != nil && t.methods[method]
}

// CountRequest records a request against the budgets. Returns a Decision
// refusing requests once any budget is exhausted.
func (c *Checker) CountRequest(raw string) Decision {
	u, err := url.Parse(raw)
	if err != nil {
		return deny("unparseable URL")
	}
	if c.maxTotal > 0 {
		n := atomic.AddInt64(&c.totalCount, 1)
		if n > c.maxTotal {
			return deny("global request budget exhausted")
		}
	}
	if t := c.findTarget(u.Host); t != nil && t.maxRequests > 0 {
		n := atomic.AddInt64(&t.requestCount, 1)
		if n > t.maxRequests {
			return deny("target request budget exhausted for " + t.host)
		}
	}
	return allow("budget ok")
}

// UsedRequests reports total counted requests (for summaries).
func (c *Checker) UsedRequests() int64 { return atomic.LoadInt64(&c.totalCount) }

// Targets returns configured target hosts.
func (c *Checker) Targets() []string {
	out := make([]string, 0, len(c.targets))
	for _, t := range c.targets {
		out = append(out, t.host)
	}
	return out
}

// HasTarget reports whether a host is configured.
func (c *Checker) HasTarget(host string) bool { return c.findTarget(host) != nil }
