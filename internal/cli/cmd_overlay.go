// CLI flag overlays: scan/discover flags are merged onto the loaded
// configuration and re-validated, so the canonical one-command workflow
// (`owntrace scan -u https://authorized.example --report=html`) goes through
// exactly the same deny-by-default validation as file configuration.
package cli

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/config"

	"gopkg.in/yaml.v3"
)

// flagSet is the narrow flag access used by overlays.
type flagSet interface {
	values(name string) []string
	str(name string) string
	boolean(name string) bool
}

// fsAdapter adapts a *flag.FlagSet to flagSet.
type fsAdapter struct{ fs *flag.FlagSet }

func (a fsAdapter) values(name string) []string { return flagValues(a.fs, name) }
func (a fsAdapter) str(name string) string      { return strFlag(a.fs, name) }
func (a fsAdapter) boolean(name string) bool    { return boolFlag(a.fs, name) }

// parseTarget parses an operator-declared target URL into (host, scheme,
// pathPrefix). A missing scheme defaults to https. A non-root path narrows
// the scope to that path prefix — the operator authorized that application,
// not the whole host.
func parseTarget(raw string) (host, scheme, pathPrefix string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", fmt.Errorf("empty target URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, perr := url.Parse(raw)
	if perr != nil {
		return "", "", "", fmt.Errorf("invalid URL: %w", perr)
	}
	if u.Host == "" {
		return "", "", "", fmt.Errorf("missing host")
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return "", "", "", fmt.Errorf("unsupported scheme %q (use http or https)", u.Scheme)
	}
	host = u.Host
	scheme = u.Scheme
	pathPrefix = strings.TrimSuffix(u.Path, "/")
	return host, scheme, pathPrefix, nil
}

// readSeedFile reads a seed list file: one URL per line, '#' comments and
// blank lines skipped.
func readSeedFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read seed list %s: %w", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("seed list %s contains no URLs", path)
	}
	return out, nil
}

// appendUnique appends v when not already present.
func appendUnique(ss []string, v string) []string {
	for _, s := range ss {
		if s == v {
			return ss
		}
	}
	return append(ss, v)
}

// scanOverlay builds the configuration overlay from scan flags. Values are
// additive (targets, inputs) or overriding (report formats, output dir,
// scope file) as documented per flag; --no-discover switches the scan to a
// stored inventory by emptying the discovery sources.
func scanOverlay(fs flagSet) func(*config.Config) error {
	return func(cfg *config.Config) error {
		// Targets: explicit, operator-declared authorization for this run.
		for _, raw := range fs.values("target") {
			host, scheme, pathPrefix, err := parseTarget(raw)
			if err != nil {
				return fmt.Errorf("--target %q: %w", raw, err)
			}
			t := config.ScopeTarget{Host: host, Schemes: []string{scheme}}
			if pathPrefix != "" {
				t.IncludePaths = []string{pathPrefix}
			}
			appendTarget(cfg, t)
			cfg.Discovery.Seeds = append(cfg.Discovery.Seeds, seedFromTarget(raw))
			cfg.Discovery.Sources = appendUnique(cfg.Discovery.Sources, "url")
		}

		// Discovery inputs.
		cfg.Discovery.OpenAPIFiles = append(cfg.Discovery.OpenAPIFiles, fs.values("openapi")...)
		cfg.Discovery.HARFiles = append(cfg.Discovery.HARFiles, fs.values("har")...)
		cfg.Workflows.Files = append(cfg.Workflows.Files, fs.values("workflow")...)
		for _, f := range fs.values("list") {
			seeds, err := readSeedFile(f)
			if err != nil {
				return err
			}
			cfg.Discovery.Seeds = append(cfg.Discovery.Seeds, seeds...)
			cfg.Discovery.Sources = appendUnique(cfg.Discovery.Sources, "url")
		}

		// Profile subset: restrict testing to a named set of profiles.
		if names := fs.values("profile"); len(names) > 0 {
			known := map[string]bool{}
			for _, p := range cfg.Auth.Profiles {
				known[p.Name] = true
			}
			for _, n := range names {
				if !known[n] {
					return fmt.Errorf("--profile %q: no such authentication profile", n)
				}
			}
			kept := make([]config.Profile, 0, len(names))
			for _, p := range cfg.Auth.Profiles {
				for _, n := range names {
					if p.Name == n {
						kept = append(kept, p)
						break
					}
				}
			}
			cfg.Auth.Profiles = kept
		}

		// Report formats and output directory overrides.
		if r := fs.str("report"); r != "" {
			var formats []string
			for _, f := range strings.Split(r, ",") {
				if f = strings.TrimSpace(f); f != "" {
					formats = append(formats, f)
				}
			}
			if len(formats) == 0 {
				return fmt.Errorf("--report: no formats given")
			}
			cfg.Report.Formats = formats
		}
		if o := fs.str("output"); o != "" {
			cfg.Session.OutputDir = o
		}

		// Scope override file replaces the configured scope entirely —
		// explicit and auditable (merged config is re-validated afterwards).
		if sf := fs.str("scope"); sf != "" {
			b, err := os.ReadFile(sf)
			if err != nil {
				return fmt.Errorf("read scope file %s: %w", sf, err)
			}
			var doc struct {
				Scope config.Scope `yaml:"scope"`
			}
			if err := yaml.Unmarshal(b, &doc); err != nil {
				return fmt.Errorf("parse scope file %s: %w", sf, err)
			}
			if len(doc.Scope.Targets) == 0 {
				// Try a bare scope document (targets at top level).
				var bare config.Scope
				if err := yaml.Unmarshal(b, &bare); err != nil || len(bare.Targets) == 0 {
					return fmt.Errorf("scope file %s contains no scope.targets", sf)
				}
				doc.Scope = bare
			}
			cfg.Scope = doc.Scope
		}

		// --no-discover: reuse a stored inventory instead of discovery.
		if fs.boolean("no-discover") {
			cfg.Discovery.Sources = nil
		}
		return nil
	}
}

// discoverOverlay applies discover --target flags: the URL declares the
// authorized scope for this run and seeds discovery.
func discoverOverlay(fs flagSet) func(*config.Config) error {
	return func(cfg *config.Config) error {
		for _, raw := range fs.values("target") {
			host, scheme, pathPrefix, err := parseTarget(raw)
			if err != nil {
				return fmt.Errorf("--target %q: %w", raw, err)
			}
			t := config.ScopeTarget{Host: host, Schemes: []string{scheme}}
			if pathPrefix != "" {
				t.IncludePaths = []string{pathPrefix}
			}
			appendTarget(cfg, t)
			cfg.Discovery.Seeds = append(cfg.Discovery.Seeds, seedFromTarget(raw))
			cfg.Discovery.Sources = appendUnique(cfg.Discovery.Sources, "url")
		}
		return nil
	}
}

// seedFromTarget normalizes a target URL into a discovery seed (scheme kept
// as declared; scheme-less targets become https).
func seedFromTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		return strings.TrimSuffix(raw, "/")
	}
	return "https://" + strings.TrimSuffix(raw, "/")
}

// appendTarget adds an operator-declared target to the scope. Declaring a
// host that is already in scope is idempotent (the CLI flag may restate the
// configured target); a genuinely new host is appended and the merged scope
// is re-validated by the caller.
func appendTarget(cfg *config.Config, t config.ScopeTarget) {
	for _, existing := range cfg.Scope.Targets {
		if existing.Host == t.Host {
			return
		}
	}
	cfg.Scope.Targets = append(cfg.Scope.Targets, t)
}
