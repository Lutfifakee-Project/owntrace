// Package config loads, validates and defaults OWNTRACE configuration.
//
// Configuration is split into two files to keep secrets out of the main
// project file:
//
//   - owntrace.yaml : scope, limits, discovery, objects, verification, safety
//   - auth.yaml     : authentication profiles (credentials) - gitignored,
//     filesystem permissions 0600, never written to reports.
//
// Credentials may also come from the environment via {{ env VAR_NAME }}.
package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Version of the configuration schema understood by this build.
const SchemaVersion = 1

// Config is the root configuration document.
type Config struct {
	Version      int          `yaml:"version" json:"version"`
	Session      Session      `yaml:"session" json:"session"`
	Scope        Scope        `yaml:"scope" json:"scope"`
	Limits       Limits       `yaml:"limits" json:"limits"`
	Auth         Auth         `yaml:"auth" json:"auth"`
	Discovery    Discovery    `yaml:"discovery" json:"discovery"`
	Objects      Objects      `yaml:"objects" json:"objects"`
	Workflows    Workflows    `yaml:"workflows" json:"workflows"`
	Verification Verification `yaml:"verification" json:"verification"`
	Safety       Safety       `yaml:"safety" json:"safety"`
	Report       Report       `yaml:"report" json:"report"`
	Retention    Retention    `yaml:"retention" json:"retention"`
	Network      Network      `yaml:"network" json:"network"`
}

// Network holds transport-level options. ProxyURL routes requests through
// an operator-provided HTTP(S) proxy (§30); the dial guard still applies to
// every resolved target address.
type Network struct {
	ProxyURL string `yaml:"proxy_url" json:"proxy_url"`
}

// Session groups run-level settings.
type Session struct {
	Name      string `yaml:"name" json:"name"`
	OutputDir string `yaml:"output_dir" json:"output_dir"`
	LogLevel  string `yaml:"log_level" json:"log_level"`
}

// ScopeTarget is one explicitly authorized target host.
type ScopeTarget struct {
	Host           string   `yaml:"host" json:"host"` // host[:port]
	Schemes        []string `yaml:"schemes" json:"schemes"`
	IncludePaths   []string `yaml:"include_paths" json:"include_paths"`
	ExcludePaths   []string `yaml:"exclude_paths" json:"exclude_paths"`
	AllowedMethods []string `yaml:"allowed_methods" json:"allowed_methods"`
	MaxRequests    int      `yaml:"max_requests" json:"max_requests"`
}

// Scope defines the authorized testing boundary. It is deny-by-default: a
// host that is not listed is out of scope, full stop.
type Scope struct {
	Targets              []ScopeTarget `yaml:"targets" json:"targets"`
	GlobalAllowedMethods []string      `yaml:"global_allowed_methods" json:"global_allowed_methods"`
	BlockedPathPatterns  []string      `yaml:"blocked_path_patterns" json:"blocked_path_patterns"`
	AllowSubdomains      bool          `yaml:"allow_subdomains" json:"allow_subdomains"`
	MaxRequestsTotal     int           `yaml:"max_requests_total" json:"max_requests_total"`
	MaxCrawlDepth        int           `yaml:"max_crawl_depth" json:"max_crawl_depth"`
	MaxCrawlPages        int           `yaml:"max_crawl_pages" json:"max_crawl_pages"`
}

// Limits bounds resource consumption.
type Limits struct {
	RatePerSecond      float64 `yaml:"rate_per_second" json:"rate_per_second"`
	Concurrency        int     `yaml:"concurrency" json:"concurrency"`
	RequestTimeoutSecs int     `yaml:"request_timeout_seconds" json:"request_timeout_seconds"`
	MaxResponseBytes   int64   `yaml:"max_response_bytes" json:"max_response_bytes"`
	MaxRedirects       int     `yaml:"max_redirects" json:"max_redirects"`
	Retries            int     `yaml:"retries" json:"retries"`
}

// IdentityProbe describes how to verify a profile's identity: an endpoint
// request made WITH that profile's credentials whose JSON response contains a
// distinguishing field (dot-separated path).
type IdentityProbe struct {
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Method   string `yaml:"method" json:"method"`
	Field    string `yaml:"field" json:"field"`
}

// Profile is one independent authentication context.
type Profile struct {
	Name     string            `yaml:"name" json:"name"`
	Type     string            `yaml:"type" json:"type"` // bearer|jwt|cookie|header|basic|none
	Token    string            `yaml:"token" json:"-"`   // resolved from secrets file or env
	Headers  map[string]string `yaml:"headers" json:"-"`
	Cookies  map[string]string `yaml:"cookies" json:"-"`
	Username string            `yaml:"username" json:"-"`
	Password string            `yaml:"password" json:"-"`
	Role     string            `yaml:"role" json:"role"` // optional role label, e.g. "admin"
	Identity IdentityProbe     `yaml:"identity" json:"identity"`
}

// Auth groups authentication profiles.
type Auth struct {
	Profiles         []Profile `yaml:"profiles" json:"-"`
	RequireDistinct  bool      `yaml:"require_distinct_identities" json:"require_distinct_identities"`
	HARProfileHeader string    `yaml:"har_profile_header" json:"har_profile_header"` // header marking HAR entries with a profile, default X-Owntrace-Profile
}

// Discovery selects and parameterizes discovery sources.
type Discovery struct {
	Sources      []string `yaml:"sources" json:"sources"` // url|har|openapi|crawl
	Seeds        []string `yaml:"seeds" json:"seeds"`
	HARFiles     []string `yaml:"har_files" json:"har_files"`
	OpenAPIFiles []string `yaml:"openapi_files" json:"openapi_files"`
	CrawlSeeds   []string `yaml:"crawl_seeds" json:"crawl_seeds"`
	// InventoryMaxAgeHours bounds how long a stored endpoint inventory may be
	// reused with --no-discover. Older inventories are rejected as stale
	// instead of silently scanned (default 720h = 30 days, set in
	// ApplyDefaults). 0 applies the default.
	InventoryMaxAgeHours int `yaml:"inventory_max_age_hours" json:"inventory_max_age_hours"`
}

// Workflows declares operator-provided application workflow files (stateful
// multi-request flows used for ownership establishment and sensitive
// business-flow testing). Disabled unless files are listed.
type Workflows struct {
	Files []string `yaml:"files" json:"files"`
}

// DeclaredObject is a user-declared object ownership mapping.
type DeclaredObject struct {
	Profile     string   `yaml:"profile" json:"profile"`
	Resource    string   `yaml:"resource" json:"resource"`
	URL         string   `yaml:"url" json:"url"` // concrete item URL with identifier
	Identifiers []string `yaml:"identifiers" json:"identifiers"`
	Tenant      string   `yaml:"tenant" json:"tenant"`
}

// CreationWorkflow describes a controlled, user-authorized object creation
// procedure used to establish confirmed ownership. Disabled unless explicitly
// enabled AND write methods are allowed.
type CreationWorkflow struct {
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	Endpoint        string   `yaml:"endpoint" json:"endpoint"` // concrete URL
	Method          string   `yaml:"method" json:"method"`
	BodyTemplate    string   `yaml:"body_template" json:"body_template"`
	ContentType     string   `yaml:"content_type" json:"content_type"`
	ExtractField    string   `yaml:"extract_field" json:"extract_field"`         // dot path in JSON response, e.g. data.id
	ItemURLTemplate string   `yaml:"item_url_template" json:"item_url_template"` // optional; {{id}} placeholder; defaults to endpoint + "/" + id
	Profiles        []string `yaml:"profiles" json:"profiles"`
	DeleteAfter     bool     `yaml:"delete_after" json:"delete_after"`
}

// Objects configures object discovery and ownership mapping.
type Objects struct {
	Declared []DeclaredObject `yaml:"declared" json:"declared"`
	Creation CreationWorkflow `yaml:"creation" json:"creation"`
	// MineCollections lists collection endpoints GETed per-profile to infer
	// ownership from listing membership (e.g. /api/orders as userA).
	MineCollections []Collection `yaml:"mine_collections" json:"mine_collections"`
}

// Collection describes an owned-collection endpoint used for ownership
// inference. The request is made as the named profile; identifiers found in
// the listing are attributed to that profile (inferred ownership).
type Collection struct {
	Profile  string   `yaml:"profile" json:"profile"`
	URL      string   `yaml:"url" json:"url"`
	Resource string   `yaml:"resource" json:"resource"`
	IDFields []string `yaml:"id_fields" json:"id_fields"` // dot paths of identifier fields in list items, default: id, *_id
}

// Verification tunes the evidence-based verification engine.
type Verification struct {
	Repeats                   int      `yaml:"repeats" json:"repeats"`
	RequireIdentitySeparation bool     `yaml:"require_identity_separation" json:"require_identity_separation"`
	CacheBust                 bool     `yaml:"cache_bust" json:"cache_bust"`
	AnonymousTest             bool     `yaml:"anonymous_test" json:"anonymous_test"`
	NestedTest                bool     `yaml:"nested_test" json:"nested_test"`
	VerticalTest              bool     `yaml:"vertical_test" json:"vertical_test"`
	AdminPathPatterns         []string `yaml:"admin_path_patterns" json:"admin_path_patterns"`
	// RestrictedProperties lists property names/dotted paths that must never
	// be readable by unauthorized principals (BOPLA policy evidence, §29).
	// When non-empty, exposure of a listed property routes the finding to
	// broken_object_property_level_authorization.
	RestrictedProperties []string `yaml:"restricted_properties" json:"restricted_properties"`
	// GraphQLTest enables the GraphQL object-level battery for operations
	// harvested from HAR traffic (§26). Default true; mutations remain
	// gated by safety.allow_write_methods.
	GraphQLTest               *bool  `yaml:"graphql_test" json:"graphql_test"`
	MinOwnerStateForConfirmed string `yaml:"min_owner_state_for_confirmed" json:"min_owner_state_for_confirmed"` // confirmed|declared|inferred
	MaxFindings               int    `yaml:"max_findings" json:"max_findings"`
}

// GraphQLTestingEnabled reports whether the GraphQL battery runs.
func (v Verification) GraphQLTestingEnabled() bool {
	return v.GraphQLTest == nil || *v.GraphQLTest
}

// Safety enforces conservative defaults in code.
type Safety struct {
	DryRun             bool `yaml:"dry_run" json:"dry_run"`
	AllowWriteMethods  bool `yaml:"allow_write_methods" json:"allow_write_methods"`
	BlockDestructive   bool `yaml:"block_destructive_paths" json:"block_destructive_paths"`
	RequireSummaryGate bool `yaml:"show_testing_summary_gate" json:"show_testing_summary_gate"`
}

// Report selects output formats.
type Report struct {
	Formats []string `yaml:"formats" json:"formats"`
	Title   string   `yaml:"title" json:"title"`
}

// Retention controls local data lifetime.
type Retention struct {
	Days int `yaml:"days" json:"days"`
}

var envRefRe = regexp.MustCompile(`\{\{\s*env\s+([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// ResolveSecret expands {{ env VAR }} references in secret strings. Literal
// values pass through unchanged.
func ResolveSecret(v string) (string, error) {
	if v == "" || !strings.Contains(v, "{{") {
		return v, nil
	}
	return envRefRe.ReplaceAllStringFunc(v, func(m string) string {
		sub := envRefRe.FindStringSubmatch(m)
		val, ok := os.LookupEnv(sub[1])
		if !ok {
			return ""
		}
		return val
	}), nil
}

// Load reads and validates the main config file and (optionally) the secrets
// file. authPath may be empty when no auth is configured.
func Load(path, authPath string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(false)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if authPath != "" {
		if err := c.loadAuth(authPath); err != nil {
			return nil, err
		}
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := c.resolveProfileSecrets(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) loadAuth(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // auth is optional
		}
		return fmt.Errorf("stat auth file: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("auth file %s has overly broad permissions %o; required: owner-only (0600)", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read auth file %s: %w", path, err)
	}
	// File format: auth:\n  profiles: [...] (matches WriteAuthTemplate).
	var wrapper struct {
		Auth Auth `yaml:"auth"`
	}
	if err := yaml.Unmarshal(raw, &wrapper); err != nil {
		return fmt.Errorf("parse auth file %s: %w", path, err)
	}
	c.Auth.Profiles = wrapper.Auth.Profiles
	return nil
}

func (c *Config) resolveProfileSecrets() error {
	for i := range c.Auth.Profiles {
		p := &c.Auth.Profiles[i]
		var err error
		if p.Token, err = ResolveSecret(p.Token); err != nil {
			return err
		}
		for k, v := range p.Headers {
			if p.Headers[k], err = ResolveSecret(v); err != nil {
				return err
			}
		}
		if p.Password, err = ResolveSecret(p.Password); err != nil {
			return err
		}
	}
	return nil
}

// ApplyDefaults fills unset fields with safe defaults.
func (c *Config) ApplyDefaults() {
	if c.Version == 0 {
		c.Version = SchemaVersion
	}
	if c.Session.OutputDir == "" {
		c.Session.OutputDir = "./owntrace-data"
	}
	if c.Session.LogLevel == "" {
		c.Session.LogLevel = "info"
	}
	if len(c.Scope.GlobalAllowedMethods) == 0 {
		c.Scope.GlobalAllowedMethods = []string{"GET", "HEAD", "OPTIONS"}
	}
	if len(c.Scope.BlockedPathPatterns) == 0 {
		c.Scope.BlockedPathPatterns = defaultBlockedPatterns()
	}
	if c.Scope.MaxRequestsTotal == 0 {
		c.Scope.MaxRequestsTotal = 2000
	}
	if c.Scope.MaxCrawlDepth == 0 {
		c.Scope.MaxCrawlDepth = 2
	}
	if c.Scope.MaxCrawlPages == 0 {
		c.Scope.MaxCrawlPages = 50
	}
	if c.Limits.RatePerSecond == 0 {
		c.Limits.RatePerSecond = 5
	}
	if c.Limits.Concurrency == 0 {
		c.Limits.Concurrency = 4
	}
	if c.Limits.RequestTimeoutSecs == 0 {
		c.Limits.RequestTimeoutSecs = 15
	}
	if c.Limits.MaxResponseBytes == 0 {
		c.Limits.MaxResponseBytes = 2 << 20 // 2 MiB
	}
	if c.Limits.MaxRedirects == 0 {
		c.Limits.MaxRedirects = 5
	}
	if c.Limits.Retries == 0 {
		c.Limits.Retries = 1
	}
	if c.Auth.HARProfileHeader == "" {
		c.Auth.HARProfileHeader = "X-Owntrace-Profile"
	}
	// A required distinct-identity check implies the verification gate.
	if c.Auth.RequireDistinct {
		c.Verification.RequireIdentitySeparation = true
	}
	if c.Verification.Repeats == 0 {
		c.Verification.Repeats = 2
	}
	if c.Verification.MinOwnerStateForConfirmed == "" {
		c.Verification.MinOwnerStateForConfirmed = "declared"
	}
	if c.Verification.AdminPathPatterns == nil {
		c.Verification.AdminPathPatterns = []string{"/admin", "admin/", "/internal/", "/manage"}
	}
	if c.Verification.MaxFindings == 0 {
		c.Verification.MaxFindings = 500
	}
	if len(c.Report.Formats) == 0 {
		c.Report.Formats = []string{"json", "markdown"}
	}
	if c.Report.Title == "" {
		c.Report.Title = "OWNTRACE Authorization Test Report"
	}
	if c.Retention.Days == 0 {
		c.Retention.Days = 30
	}
	if len(c.Discovery.Sources) == 0 {
		c.Discovery.Sources = []string{"url", "openapi", "har"}
	}
	if c.Discovery.InventoryMaxAgeHours == 0 {
		c.Discovery.InventoryMaxAgeHours = 720
	}
}

// ValidateNetwork checks the optional proxy configuration (§30).
func (c *Config) validateNetwork() error {
	if strings.TrimSpace(c.Network.ProxyURL) == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(c.Network.ProxyURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("network.proxy_url %q is invalid (want http://host[:port])", c.Network.ProxyURL)
	}
	return nil
}

// defaultBlockedPatterns are paths OWNTRACE refuses to touch by default even
// if in scope: operations that could destroy data or change state.
func defaultBlockedPatterns() []string {
	return []string{
		`(?i)logout`, `(?i)signout`, `(?i)delete`, `(?i)destroy`, `(?i)remove`,
		`(?i)password`, `(?i)payment`, `(?i)checkout`, `(?i)purchase`, `(?i)billing`,
		`(?i)unsubscribe`, `(?i)cancel`, `(?i)revoke`, `(?i)reset`, `(?i)transfer`,
		`(?i)refund`, `(?i)payout`, `(?i)close`, `(?i)disable`, `(?i)deactivate`,
	}
}

// Validate checks structural sanity with clear, actionable errors.
func (c *Config) Validate() error {
	if err := c.validateNetwork(); err != nil {
		return err
	}
	if c.Version != SchemaVersion {
		return fmt.Errorf("config version %d not supported (want %d)", c.Version, SchemaVersion)
	}
	if len(c.Scope.Targets) == 0 {
		return fmt.Errorf("scope.targets must list at least one explicitly authorized host")
	}
	seenHosts := map[string]bool{}
	for i, t := range c.Scope.Targets {
		if t.Host == "" {
			return fmt.Errorf("scope.targets[%d].host is empty", i)
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t.Host), "/"))
		if strings.Contains(host, "://") {
			return fmt.Errorf("scope.targets[%d].host %q must not include a scheme; use the schemes field", i, t.Host)
		}
		if seenHosts[host] {
			return fmt.Errorf("scope.targets[%d]: duplicate host %q", i, host)
		}
		seenHosts[host] = true
	}
	profiles := map[string]bool{}
	for i, p := range c.Auth.Profiles {
		if p.Name == "" {
			return fmt.Errorf("auth.profiles[%d].name is empty", i)
		}
		if profiles[p.Name] {
			return fmt.Errorf("auth.profiles[%d]: duplicate profile name %q", i, p.Name)
		}
		profiles[p.Name] = true
		switch strings.ToLower(p.Type) {
		case "bearer", "jwt", "cookie", "header", "basic", "none":
		default:
			return fmt.Errorf("auth.profiles[%d] (%s): unsupported type %q", i, p.Name, p.Type)
		}
		if p.Type == "basic" && (p.Username == "" || p.Password == "") {
			return fmt.Errorf("auth.profiles[%d] (%s): basic auth requires username and password", i, p.Name)
		}
	}
	names := c.profileNames()
	for i, d := range c.Objects.Declared {
		if d.Profile == "" || len(d.Identifiers) == 0 || d.URL == "" {
			return fmt.Errorf("objects.declared[%d]: profile, url and identifiers are required", i)
		}
		if !profiles[d.Profile] {
			return fmt.Errorf("objects.declared[%d]: profile %q is not defined in auth (profiles: %v)", i, d.Profile, names)
		}
	}
	for i, col := range c.Objects.MineCollections {
		if col.URL == "" {
			return fmt.Errorf("objects.mine_collections[%d]: url is required", i)
		}
		if !profiles[col.Profile] {
			return fmt.Errorf("objects.mine_collections[%d]: profile %q is not defined in auth", i, col.Profile)
		}
	}
	if c.Objects.Creation.Enabled {
		w := c.Objects.Creation
		if w.Endpoint == "" || w.ExtractField == "" || len(w.Profiles) == 0 {
			return fmt.Errorf("objects.creation: endpoint, extract_field and profiles are required when enabled")
		}
		if !c.Safety.AllowWriteMethods {
			return fmt.Errorf("objects.creation.enabled requires safety.allow_write_methods=true")
		}
		for _, p := range w.Profiles {
			if !profiles[p] {
				return fmt.Errorf("objects.creation: profile %q is not defined in auth", p)
			}
		}
	}
	if c.Verification.Repeats < 1 || c.Verification.Repeats > 5 {
		return fmt.Errorf("verification.repeats must be between 1 and 5 (got %d)", c.Verification.Repeats)
	}
	switch c.Verification.MinOwnerStateForConfirmed {
	case "declared", "confirmed":
		// ok — inferred and unknown can never be a confirmation floor (§4.2)
	default:
		return fmt.Errorf("verification.min_owner_state_for_confirmed must be \"declared\" or \"confirmed\" (got %q); inferred and unknown ownership may never support confirmation", c.Verification.MinOwnerStateForConfirmed)
	}
	for _, f := range c.Report.Formats {
		switch f {
		case "json", "markdown", "html", "csv":
		default:
			return fmt.Errorf("report.formats: unsupported format %q (json|markdown|html|csv)", f)
		}
	}
	if c.Limits.Concurrency < 1 || c.Limits.Concurrency > 64 {
		return fmt.Errorf("limits.concurrency must be 1..64 (got %d)", c.Limits.Concurrency)
	}
	if c.Limits.RatePerSecond <= 0 || c.Limits.RatePerSecond > 100 {
		return fmt.Errorf("limits.rate_per_second must be >0 and <=100 (got %v)", c.Limits.RatePerSecond)
	}
	return nil
}

func (c *Config) profileNames() []string {
	out := make([]string, 0, len(c.Auth.Profiles))
	for _, p := range c.Auth.Profiles {
		out = append(out, p.Name)
	}
	return out
}

// Profile returns the named profile, or nil.
func (c *Config) Profile(name string) *Profile {
	for i := range c.Auth.Profiles {
		if c.Auth.Profiles[i].Name == name {
			return &c.Auth.Profiles[i]
		}
	}
	return nil
}

// ProfileNames returns configured profile names.
func (c *Config) ProfileNames() []string { return c.profileNames() }

// RedactedCopy returns a deep copy safe for embedding in reports/sessions:
// all credential material removed. Values become presence markers.
func (c *Config) RedactedCopy() *Config {
	cc := *c
	cc.Auth.Profiles = make([]Profile, len(c.Auth.Profiles))
	for i, p := range c.Auth.Profiles {
		p.Token = presence(p.Token)
		p.Password = presence(p.Password)
		p.Username = presence(p.Username)
		if p.Headers != nil {
			h := make(map[string]string, len(p.Headers))
			for k := range p.Headers {
				h[k] = "‹redacted›"
			}
			p.Headers = h
		}
		if p.Cookies != nil {
			ck := make(map[string]string, len(p.Cookies))
			for k := range p.Cookies {
				ck[k] = "‹redacted›"
			}
			p.Cookies = ck
		}
		cc.Auth.Profiles[i] = p
	}
	return &cc
}

func presence(v string) string {
	if v == "" {
		return ""
	}
	return "‹redacted›"
}

// DefaultBlockedPatterns exposes the default destructive-path denylist.
func DefaultBlockedPatterns() []string { return defaultBlockedPatterns() }

// WriteTemplate writes an annotated starter owntrace.yaml.
func WriteTemplate(path string) error {
	tmpl := `# OWNTRACE configuration (v1)
# Full reference: docs/configuration.md
version: 1

session:
  name: "first-scan"
  output_dir: "./owntrace-data"
  log_level: "info"

# ---------------------------------------------------------------- scope ----
# Deny-by-default: only hosts listed here may receive requests.
scope:
  targets:
    - host: "127.0.0.1:8080"          # host[:port] of the authorized target
      schemes: ["http", "https"]
      include_paths: ["/"]            # limit testing to these path prefixes
      exclude_paths: ["/admin/logout"]
      allowed_methods: ["GET", "HEAD", "OPTIONS"]   # per-target methods
      max_requests: 500               # hard budget for this target
  global_allowed_methods: ["GET", "HEAD", "OPTIONS"]
  # Paths matching these regexes are never requested (destructive ops).
  # blocked_path_patterns: ["(?i)delete", "(?i)password"]
  allow_subdomains: false
  max_requests_total: 2000
  max_crawl_depth: 2
  max_crawl_pages: 50

limits:
  rate_per_second: 5        # global requests/second ceiling
  concurrency: 4
  request_timeout_seconds: 15
  max_response_bytes: 2097152   # 2 MiB body cap
  max_redirects: 5
  retries: 1

# ----------------------------------------------------------------- auth ----
# Credentials live in auth.yaml (0600, gitignored) or env references.
auth:
  require_distinct_identities: true
  # profiles are defined in auth.yaml, e.g.:
  # - name: userA
  #   type: bearer
  #   token: "{{ env OT_USERA_TOKEN }}"
  #   identity: { endpoint: "/api/me", method: "GET", field: "user.id" }

# ------------------------------------------------------------- discovery ---
discovery:
  sources: ["url", "openapi", "har"]
  seeds: []
  har_files: []
  openapi_files: []

# --------------------------------------------------------------- objects ---
objects:
  declared: []                 # user-declared ownership, e.g.:
  # - profile: userA
  #   resource: order
  #   url: "http://127.0.0.1:8080/api/orders/1001"
  #   identifiers: ["1001"]
  mine_collections: []         # listing endpoints per-profile for ownership inference
  creation:
    enabled: false             # requires safety.allow_write_methods=true

# ----------------------------------------------------------- verification --
verification:
  repeats: 2                       # repeatability control
  require_identity_separation: true
  cache_bust: true
  anonymous_test: true
  nested_test: true
  vertical_test: true
  admin_path_patterns: ["/admin", "admin/", "/internal/"]

# ---------------------------------------------------------------- safety ---
safety:
  dry_run: false
  allow_write_methods: false       # POST/PUT/PATCH stay untested until true
  block_destructive_paths: true

report:
  formats: ["json", "markdown"]
  title: "OWNTRACE Authorization Test Report"

retention:
  days: 30
`
	return os.WriteFile(path, []byte(tmpl), 0o600)
}

// WriteAuthTemplate writes a starter auth.yaml with 0600 permissions.
func WriteAuthTemplate(path string) error {
	tmpl := `# OWNTRACE authentication profiles (SECRETS - do not commit, chmod 600)
# Credentials are never written into reports or logs; export a redacted copy
# with: owntrace config show --redacted
auth:
  profiles:
    - name: userA
      type: bearer
      token: "{{ env OT_USERA_TOKEN }}"   # or paste a test token (labs only)
      identity:                            # used to verify identity separation
        endpoint: "/api/v1/profile"
        method: "GET"
        field: "user.id"
    - name: userB
      type: bearer
      token: "{{ env OT_USERB_TOKEN }}"
      identity:
        endpoint: "/api/v1/profile"
        method: "GET"
        field: "user.id"
    - name: anon
      type: none
`
	return os.WriteFile(path, []byte(tmpl), 0o600)
}

// EnsureDir creates a directory with restrictive permissions.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o700)
}

// GitignorePath is the standard ignore entry for the secrets file.
const GitignorePath = "auth.yaml"
