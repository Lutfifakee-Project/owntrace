// Package httpclient provides OWNTRACE's controlled HTTP client.
//
// Every request is gated by the safety engine (scope, budgets, rate limits),
// redirects are followed manually hop-by-hop with scope validation of every
// destination, response bodies are bounded, and exchanges are captured in a
// redacted, evidence-ready form.
package httpclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/version"
)

// Hop is one redirect step.
type Hop struct {
	URL       string `json:"url"`
	Status    int    `json:"status"`
	Location  string `json:"location,omitempty"`
	InScope   bool   `json:"in_scope"`
	ScopeNote string `json:"scope_note,omitempty"`
}

// Exchange is the captured result of one logical request (including its
// redirect chain). Bodies are already truncated and credential-redacted.
type Exchange struct {
	RequestURL     string            `json:"request_url"` // redacted
	Method         string            `json:"method"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"` // redacted
	RequestBody    string            `json:"request_body,omitempty"`    // redacted, truncated

	Status          int               `json:"status"`
	ContentType     string            `json:"content_type,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"` // redacted
	Body            string            `json:"body,omitempty"`             // redacted, truncated
	// RawBody is the unredacted, size-bounded response body. In-memory only
	// (never serialized): consumed by the workflow engine for exact value
	// extraction; evidence and reports use the redacted Body.
	RawBody       string `json:"-"`
	BodyTruncated bool   `json:"body_truncated,omitempty"`
	BodyLen       int    `json:"body_len"`            // pre-redaction length
	FinalURL      string `json:"final_url,omitempty"` // redacted
	Redirects     []Hop  `json:"redirects,omitempty"`
	ScopeBlocked  bool   `json:"scope_blocked,omitempty"` // a redirect hop left scope
	// SafetyBlocked marks an exchange whose request was refused by the safety
	// guards BEFORE it was sent (destructive-path denylist, out-of-scope
	// deny-by-default, or a write-method refusal). Coverage accounting must
	// never count such an exchange as executed.
	SafetyBlocked bool      `json:"safety_blocked,omitempty"`
	DurationMs    int64     `json:"duration_ms"`
	Err           string    `json:"error,omitempty"`
	At            time.Time `json:"at"`
}

// Succeeded reports a completed HTTP exchange (any status code).
func (x *Exchange) Succeeded() bool { return x != nil && x.Err == "" && x.Status > 0 }

// Is2xx reports an HTTP success status.
func (x *Exchange) Is2xx() bool { return x != nil && x.Status >= 200 && x.Status < 300 }

// IsRedirect reports a 3xx with a Location header.
func (x *Exchange) IsRedirect() bool {
	return x != nil && x.Status >= 300 && x.Status < 400 && x.ResponseHeaders["Location"] != ""
}

// IsClientError reports 4xx.
func (x *Exchange) IsClientError() bool { return x != nil && x.Status >= 400 && x.Status < 500 }

// CacheEvidence extracts cache-related response headers for FP analysis.
func (x *Exchange) CacheEvidence() string {
	if x == nil {
		return ""
	}
	var parts []string
	for _, h := range []string{"Cache-Control", "Age", "X-Cache", "X-Varnish", "X-Cache-Hit", "CF-Cache-Status", "Expires", "ETag", "Last-Modified"} {
		if v, ok := x.ResponseHeaders[h]; ok && v != "" {
			parts = append(parts, h+": "+v)
		}
	}
	return strings.Join(parts, "; ")
}

// Client wraps net/http with OWNTRACE controls.
type Client struct {
	http         *http.Client
	safety       *safety.Engine
	log          *logger.Logger
	maxBody      int64
	maxRedirects int
	maxRetries   int
	timeout      time.Duration
	guard        *dialGuard
}

// WithLookup overrides the DNS resolver used by the dial guard (tests).
func (c *Client) WithLookup(fn LookupFunc) *Client {
	if c.guard != nil {
		c.guard.lookup = fn
	}
	return c
}

// New builds a client. Keep-alives are enabled by the default transport;
// timeouts and limits come from config.
func New(se *safety.Engine, log *logger.Logger, timeout time.Duration, maxBody int64, maxRedirects, maxRetries int) *Client {
	if maxBody <= 0 {
		maxBody = 2 << 20
	}
	if maxRedirects <= 0 {
		maxRedirects = 5
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	transport := &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		MaxConnsPerHost:     16,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  false,
	}
	guard := newDialGuard(nil)
	transport.DialContext = guard.DialContext
	return &Client{
		http: &http.Client{
			Transport: transport,
			// Redirects handled manually for scope validation.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: timeout,
		},
		safety: se, log: log,
		maxBody: maxBody, maxRedirects: maxRedirects, maxRetries: maxRetries, timeout: timeout,
		guard: guard,
	}
}

// Options for a single request.
type Options struct {
	Headers map[string]string
	Body    []byte
	// ContentType overrides the derived content type for the body.
	ContentType string
}

// Do performs one logical request with redirects, safety gating, retries and
// bounded reads. It never returns a nil Exchange; transport errors land in
// Exchange.Err. The context MUST be respected for cancellation.
// SetProxy routes requests through an explicit HTTP(S) proxy (§30). The
// dial guard still governs every target: destination hosts are resolved and
// validated against the private/link-local/metadata blocklist before any
// proxied connect, so a proxy cannot launder out-of-scope dials.
func (c *Client) SetProxy(proxyURL string) error {
	u, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid proxy URL %q (want http://host[:port])", proxyURL)
	}
	if tr, ok := c.http.Transport.(*http.Transport); ok {
		tr.Proxy = http.ProxyURL(u)
		return nil
	}
	return fmt.Errorf("transport does not support proxy configuration")
}

func (c *Client) Do(ctx context.Context, method, rawURL string, opts Options) *Exchange {
	start := time.Now().UTC()
	x := &Exchange{Method: strings.ToUpper(method), RequestURL: redact.URL(rawURL), At: start}

	current := rawURL
	var hops []Hop
	for hop := 0; ; hop++ {
		if hop > 0 {
			x.RequestURL = redact.URL(current)
		}
		single := c.doSingle(ctx, method, current, opts, x)
		if !single.Succeeded() {
			x.Err = single.Err
			x.SafetyBlocked = single.SafetyBlocked
			x.DurationMs = time.Since(start).Milliseconds()
			x.Redirects = hops
			return x
		}
		x.Status = single.Status
		x.ResponseHeaders = single.ResponseHeaders
		x.Body = single.Body
		x.RawBody = single.RawBody
		x.BodyTruncated = single.BodyTruncated
		x.BodyLen = single.BodyLen
		x.ContentType = single.ContentType
		x.FinalURL = redact.URL(current)
		x.RequestBody = single.RequestBody
		x.RequestHeaders = single.RequestHeaders

		if !single.IsRedirect() || hop >= c.maxRedirects {
			break
		}
		loc, _ := url.Parse(single.ResponseHeaders["Location"])
		base, _ := url.Parse(current)
		next := base.ResolveReference(loc)
		// Scope-validate the redirect destination BEFORE following it.
		d := c.safety.Scope.Check("GET", next.String())
		hopRec := Hop{URL: redact.URL(next.String()), Status: single.Status,
			Location: redact.URL(single.ResponseHeaders["Location"]), InScope: d.Allowed, ScopeNote: d.Reason}
		hops = append(hops, hopRec)
		if !d.Allowed {
			x.ScopeBlocked = true
			x.SafetyBlocked = true
			c.log.Warnf("redirect to out-of-scope %s blocked (%s)", redact.URL(next.String()), d.Reason)
			break
		}
		current = next.String()
		opts.Body = nil // RFC: POST redirect becomes GET on 303; keep method for 307/308 simplicity but drop body unless 307/308
		if single.Status == 301 || single.Status == 302 || single.Status == 303 {
			if method != "HEAD" {
				method = "GET"
			}
		}
	}
	x.Redirects = hops
	x.DurationMs = time.Since(start).Milliseconds()
	return x
}

func (c *Client) doSingle(ctx context.Context, method, rawURL string, opts Options, parent *Exchange) *Exchange {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Only transport-level failures retry; backoff briefly.
			select {
			case <-ctx.Done():
				return errExchange(parent, method, rawURL, "cancelled")
			case <-time.After(250 * time.Millisecond):
			}
		}
		if err := c.safety.Reserve(ctx, method, rawURL); err != nil {
			x := errExchange(parent, method, rawURL, err.Error())
			// Refusals by the safety policy happened BEFORE any wire activity:
			// they are safety-skips, never executed requests.
			if errors.Is(err, safety.ErrOutOfScope) || errors.Is(err, safety.ErrMethodNotAllowed) {
				x.SafetyBlocked = true
			}
			return x
		}
		res, err := c.attempt(ctx, method, rawURL, opts)
		c.safety.Release()
		if err != nil {
			if errors.Is(err, context.Canceled) || isCtxErr(ctx) {
				return errExchange(parent, method, rawURL, "cancelled")
			}
			lastErr = err
			if attempt < c.maxRetries {
				c.log.Debugf("retry %d for %s %s after error: %v", attempt+1, method, redact.URL(rawURL), err)
				continue
			}
			return errExchange(parent, method, rawURL, lastErr.Error())
		}
		return res
	}
	return errExchange(parent, method, rawURL, "unreachable")
}

func isCtxErr(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (c *Client) attempt(ctx context.Context, method, rawURL string, opts Options) (*Exchange, error) {
	body := bytes.NewReader(opts.Body)
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", "*/*")
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}
	if opts.ContentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", opts.ContentType)
	}

	reqHeaders := map[string]string{}
	for k, vv := range req.Header {
		reqHeaders[k] = redact.HeaderValue(k, strings.Join(vv, ", "))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	x := &Exchange{
		Method:         method,
		RequestURL:     redact.URL(rawURL),
		RequestHeaders: reqHeaders,
		Status:         resp.StatusCode,
		At:             time.Now().UTC(),
	}
	x.ResponseHeaders = map[string]string{}
	for k, vv := range resp.Header {
		x.ResponseHeaders[k] = redact.HeaderValue(k, strings.Join(vv, ", "))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		x.ContentType = ct
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.Atoi(cl); err == nil {
			x.BodyLen = n
		}
	}
	// Bounded read: maxBody+1 to detect truncation.
	lr := io.LimitReader(resp.Body, c.maxBody+1)
	raw, readErr := io.ReadAll(lr)
	x.BodyLen = len(raw)
	if int64(len(raw)) > c.maxBody {
		x.BodyTruncated = true
		raw = raw[:c.maxBody]
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		x.Err = fmt.Sprintf("read body: %v", readErr)
	}
	// RawBody keeps the unredacted (still size-bounded) body IN MEMORY ONLY
	// for engines that must replay exact response values (workflow state
	// extraction, §25). It is never serialized: json:"-" keeps it out of
	// evidence, reports and exports, which use the redacted Body.
	x.RawBody = string(raw)
	x.Body = redact.BodyForEvidence(x.ContentType, raw)
	if opts.Body != nil {
		x.RequestBody = redact.Text(utilClamp(string(opts.Body), int(c.maxBody)))
	}
	if loc := resp.Header.Get("Location"); loc != "" && x.ResponseHeaders != nil {
		// Ensure Location is present (redacted) for redirect handling.
		x.ResponseHeaders["Location"] = redact.URL(loc)
	}
	return x, nil
}

func utilClamp(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…[truncated]"
}

func errExchange(parent *Exchange, method, rawURL, msg string) *Exchange {
	return &Exchange{
		Method:     method,
		RequestURL: redact.URL(rawURL),
		Err:        msg,
		At:         time.Now().UTC(),
	}
}

// RedactBodyForEvidence is exposed for other components (evidence engine,
// discovery parsers) that capture bodies outside the client.
func RedactBodyForEvidence(contentType string, raw []byte) string {
	return redact.BodyForEvidence(contentType, raw)
}
