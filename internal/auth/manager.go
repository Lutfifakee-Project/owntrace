// Package auth manages independent authentication profiles.
//
// Invariants:
//   - Every request is associated with an explicit profile; there is no
//     implicit or ambient credential context.
//   - Credentials are applied at request time and never persisted in reports,
//     logs or evidence (redaction handles captured values).
//   - Profile identity separation is verified via configured identity probes
//     before cross-account testing; indistinct identities abort the test.
package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/util"
)

// Manager owns the resolved profiles.
type Manager struct {
	cfg      *config.Config
	log      *logger.Logger
	profiles map[string]*config.Profile
}

// New builds the manager from configuration.
func New(cfg *config.Config, log *logger.Logger) (*Manager, error) {
	m := &Manager{cfg: cfg, log: log, profiles: map[string]*config.Profile{}}
	for i := range cfg.Auth.Profiles {
		p := &cfg.Auth.Profiles[i]
		if _, dup := m.profiles[p.Name]; dup {
			return nil, fmt.Errorf("duplicate auth profile %q", p.Name)
		}
		m.profiles[p.Name] = p
	}
	return m, nil
}

// AnonymousProfile is the implicit no-credential profile, always available.
const AnonymousProfile = "anon"

// Profile returns a profile by name; the anonymous profile is implicit.
func (m *Manager) Profile(name string) (*config.Profile, error) {
	if name == "" || name == AnonymousProfile {
		return &config.Profile{Name: AnonymousProfile, Type: "none"}, nil
	}
	p, ok := m.profiles[name]
	if !ok {
		return nil, fmt.Errorf("unknown auth profile %q (configured: %v)", name, m.Names())
	}
	return p, nil
}

// Names returns configured profile names (sorted).
func (m *Manager) Names() []string {
	out := make([]string, 0, len(m.profiles))
	for n := range m.profiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Headers returns the concrete headers a profile must send, resolved and
// redaction-safe for logging.
func (m *Manager) Headers(name string) (map[string]string, error) {
	p, err := m.Profile(name)
	if err != nil {
		return nil, err
	}
	h := map[string]string{}
	switch strings.ToLower(p.Type) {
	case "bearer", "jwt":
		if p.Token != "" {
			h["Authorization"] = "Bearer " + p.Token
		} else {
			return nil, fmt.Errorf("profile %q: bearer token is empty", name)
		}
	case "header":
		if len(p.Headers) == 0 {
			return nil, fmt.Errorf("profile %q: header auth requires headers", name)
		}
		for k, v := range p.Headers {
			h[k] = v
		}
	case "cookie":
		if len(p.Cookies) == 0 {
			return nil, fmt.Errorf("profile %q: cookie auth requires cookies", name)
		}
		var parts []string
		for k, v := range p.Cookies {
			parts = append(parts, k+"="+v)
		}
		h["Cookie"] = strings.Join(parts, "; ")
	case "basic":
		h["Authorization"] = "Basic " + basicAuth(p.Username, p.Password)
	case "none", "":
		// anonymous: no credentials
	default:
		return nil, fmt.Errorf("profile %q: unsupported type %q", name, p.Type)
	}
	return h, nil
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// IdentityCheck is the result of one identity probe.
type IdentityCheck struct {
	Profile     string `json:"profile"`
	Fingerprint string `json:"fingerprint"` // resolved identity value (redacted if credential-like)
	OK          bool   `json:"ok"`
	Detail      string `json:"detail,omitempty"`
}

// SeparationResult summarizes identity separation across profiles.
type SeparationResult struct {
	Checks   []IdentityCheck `json:"checks"`
	Distinct bool            `json:"distinct"`
	Verified bool            `json:"verified"` // all probes succeeded and all values distinct
	Detail   string          `json:"detail,omitempty"`
}

// VerifySeparation probes each profile's identity endpoint and verifies that
// resolved identities are pairwise distinct. If a profile has no identity
// probe configured, it is reported as unverified — callers decide whether
// that blocks testing (config.Verification.RequireIdentitySeparation).
func (m *Manager) VerifySeparation(ctx context.Context, client *httpclient.Client, profiles []string) *SeparationResult {
	res := &SeparationResult{Distinct: true}
	seen := map[string]string{}
	var missing []string
	for _, name := range profiles {
		if name == "" || name == AnonymousProfile {
			res.Checks = append(res.Checks, IdentityCheck{Profile: AnonymousProfile, OK: true,
				Fingerprint: "(anonymous)", Detail: "no credentials by design"})
			continue
		}
		p, err := m.Profile(name)
		if err != nil {
			res.Checks = append(res.Checks, IdentityCheck{Profile: name, Detail: err.Error()})
			res.Distinct = false
			continue
		}
		if p.Identity.Endpoint == "" {
			missing = append(missing, name)
			res.Checks = append(res.Checks, IdentityCheck{Profile: name, Detail: "no identity probe configured"})
			continue
		}
		fp, detail, ok := m.probe(ctx, client, p)
		res.Checks = append(res.Checks, IdentityCheck{Profile: name, Fingerprint: fp, OK: ok, Detail: detail})
		if !ok {
			continue
		}
		if prev, dup := seen[fp]; dup {
			res.Distinct = false
			res.Detail = fmt.Sprintf("profiles %s and %s resolve to the same identity fingerprint — credentials do not represent distinct users", prev, name)
			m.log.Errorf("identity separation FAILED: %s", res.Detail)
		} else {
			seen[fp] = name
		}
	}
	res.Verified = res.Distinct && len(missing) == 0 && len(seen) == len(countReal(profiles))
	if len(missing) > 0 {
		res.Detail = strings.TrimSpace(res.Detail + " identity unverified for: " + strings.Join(missing, ", "))
	}
	// Surface the first concrete failure so the summary explains itself.
	if !res.Verified && res.Detail == "" {
		for _, c := range res.Checks {
			if !c.OK && c.Detail != "" {
				res.Detail = fmt.Sprintf("%s: %s", c.Profile, c.Detail)
				break
			}
		}
	}
	return res
}

func countReal(profiles []string) []string {
	var out []string
	for _, p := range profiles {
		if p != "" && p != AnonymousProfile {
			out = append(out, p)
		}
	}
	return out
}

func (m *Manager) probe(ctx context.Context, client *httpclient.Client, p *config.Profile) (string, string, bool) {
	url := p.Identity.Endpoint
	if !strings.Contains(url, "://") {
		// Relative endpoints need an absolute base; profiles configured with a
		// relative endpoint rely on the caller-provided client default base.
		return "", fmt.Sprintf("identity endpoint %q is relative; provide an absolute URL in the profile", url), false
	}
	headers, err := m.Headers(p.Name)
	if err != nil {
		return "", err.Error(), false
	}
	x := client.Do(ctx, orGET(p.Identity.Method), url, httpclient.Options{Headers: headers})
	if !x.Succeeded() {
		return "", "identity probe failed: " + x.Err, false
	}
	if !x.Is2xx() {
		return "", fmt.Sprintf("identity probe returned HTTP %d", x.Status), false
	}
	v, ok := util.GetPath(util.DecodeJSONLoose([]byte(x.Body)), p.Identity.Field)
	if !ok {
		return "", fmt.Sprintf("identity field %q not found in probe response", p.Identity.Field), false
	}
	val := util.FirstString(v)
	if val == "" {
		return "", fmt.Sprintf("identity field %q resolved to an empty value", p.Identity.Field), false
	}
	// The fingerprint may itself be sensitive (user ID, e-mail). Redact PII
	// while keeping distinctness (fingerprint hashing is stable).
	return redact.Text(val), "", true
}

func orGET(m string) string {
	if strings.TrimSpace(m) == "" {
		return "GET"
	}
	return strings.ToUpper(m)
}
