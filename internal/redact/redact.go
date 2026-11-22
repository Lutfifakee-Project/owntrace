// Package redact removes credentials and personal data from anything OWNTRACE
// stores, logs or exports. Redaction is applied at the boundary where data is
// captured, never left to the presentation layer, so a forgotten formatter
// cannot leak a secret.
package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

func utilDecode(s string) (any, error) {
	var v any
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func utilMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Marker wraps a redacted value. The short hash lets reports compare two
// redacted values for equality without revealing the underlying secret.
const Marker = "‹redacted"

// sensitiveHeaderNames is the set of HTTP header names that must never be
// emitted verbatim. Comparison is case-insensitive.
var sensitiveHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"api-key":             true,
	"apikey":              true,
	"x-auth-token":        true,
	"x-access-token":      true,
	"x-session-token":     true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
	"secret":              true,
	"private-key":         true,
}

// SensitiveHeader reports whether an HTTP header name carries credentials.
func SensitiveHeader(name string) bool {
	return sensitiveHeaderNames[strings.ToLower(strings.TrimSpace(name))]
}

// sensitiveJSONKeys are substring matches applied case-insensitively to JSON
// object keys. A key matching one of these has its value redacted.
var sensitiveJSONKeys = []string{
	"password", "passwd", "passphrase", "secret", "token", "api_key", "apikey",
	"api-key", "authorization", "credential", "private_key", "privatekey",
	"access_token", "refresh_token", "id_token", "session", "cookie", "auth",
	"client_secret", "signature", "pin", "otp",
}

// SensitiveJSONKey reports whether a JSON field name looks credential-like.
func SensitiveJSONKey(key string) bool {
	lk := strings.ToLower(strings.TrimSpace(key))
	if lk == "" {
		return false
	}
	for _, frag := range sensitiveJSONKeys {
		if strings.Contains(lk, frag) {
			return true
		}
	}
	return false
}

var (
	jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	// Looser JWT variant (unsigned / malformed) still worth catching.
	jwtLooseRe     = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`)
	bearerRe       = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}`)
	hexSecretRe    = regexp.MustCompile(`\b[a-f0-9]{40,}\b`)
	base64SecretRe = regexp.MustCompile(`\b[A-Za-z0-9+/]{48,}={0,2}\b`)
	emailRe        = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

// Fingerprint returns a short, stable, non-reversible identifier for a secret
// so that two occurrences of the same credential can still be correlated.
func Fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

// Value redacts a single credential-looking value, preserving a correlation
// fingerprint: `‹redacted:ab12cd34›`.
func Value(v string) string {
	if v == "" {
		return v
	}
	return Marker + ":" + Fingerprint(v) + "›"
}

// HeaderValue redacts an HTTP header value. Non-sensitive headers pass through
// unchanged; sensitive ones are replaced wholesale with a fingerprint marker.
func HeaderValue(name, value string) string {
	if SensitiveHeader(name) {
		return Value(value)
	}
	return Text(value)
}

// Text scrubs credential-shaped strings embedded in free text, JSON bodies or
// URLs. Personal e-mail addresses are redacted as well (PII policy) while
// keeping a stable fingerprint so evidence remains comparable.
func Text(s string) string {
	if s == "" {
		return s
	}
	s = jwtRe.ReplaceAllStringFunc(s, func(m string) string { return Value(m) })
	s = jwtLooseRe.ReplaceAllStringFunc(s, func(m string) string { return Value(m) })
	s = bearerRe.ReplaceAllStringFunc(s, func(m string) string { return Value(m) })
	s = hexSecretRe.ReplaceAllStringFunc(s, func(m string) string { return Value(m) })
	s = base64SecretRe.ReplaceAllStringFunc(s, func(m string) string { return Value(m) })
	s = emailRe.ReplaceAllStringFunc(s, func(m string) string { return Value(m) })
	return s
}

// BodyForEvidence renders a raw response body safe for storage: credential-
// shaped strings and PII are redacted, and the body is truncated to limit.
func BodyForEvidence(contentType string, raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	const maxBody = 64 << 10 // 64 KiB evidence cap
	s := string(raw)
	if len(s) > maxBody {
		s = s[:maxBody] + "…[truncated]"
	}
	if strings.Contains(strings.ToLower(contentType), "json") {
		if v, err := utilDecode(s); err == nil && v != nil {
			sanitized := JSONBody(v)
			if b, err := utilMarshal(sanitized); err == nil {
				return string(b)
			}
		}
	}
	return Text(s)
}

// URL redacts credentials that may appear in a URL (userinfo, token query
// parameters) while leaving the address usable for reproduction.
var sensitiveQueryParams = map[string]bool{
	"token": true, "access_token": true, "refresh_token": true, "api_key": true,
	"apikey": true, "api-key": true, "key": true, "secret": true, "password": true,
	"session": true, "sessionid": true, "session_id": true, "sid": true, "auth": true,
	"jwt": true, "sig": true, "signature": true,
}

func URL(raw string) string {
	if raw == "" {
		return raw
	}
	// Redact userinfo (user:pass@host).
	if at := strings.Index(raw, "@"); at > 0 && strings.Contains(raw[:at], "://") {
		schemeEnd := strings.Index(raw, "://") + 3
		raw = raw[:schemeEnd] + Value(raw[schemeEnd:at]) + raw[at:]
	}
	// Redact sensitive query parameters.
	qStart := strings.IndexByte(raw, '?')
	if qStart < 0 {
		return raw
	}
	head, query := raw[:qStart+1], raw[qStart+1:]
	parts := strings.Split(query, "&")
	for i, p := range parts {
		eq := strings.IndexByte(p, '=')
		var k, v string
		if eq < 0 {
			k = p
		} else {
			k, v = p[:eq], p[eq+1:]
		}
		if sensitiveQueryParams[strings.ToLower(k)] {
			v = Value(v)
		} else {
			v = Text(v)
		}
		parts[i] = k + "=" + v
	}
	return head + strings.Join(parts, "&")
}

// Headers redacts a header map into a copy safe for storage and export.
func Headers(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = HeaderValue(k, v)
	}
	return out
}

// JSONBody walks a decoded JSON value and redacts credential-like fields and
// secret-shaped strings. It returns the sanitized value; callers re-serialize.
func JSONBody(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if SensitiveJSONKey(k) {
				out[k] = Value(toString(val))
				continue
			}
			out[k] = JSONBody(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = JSONBody(val)
		}
		return out
	case string:
		return Text(t)
	default:
		return v
	}
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return "‹redacted-value›"
	}
}
