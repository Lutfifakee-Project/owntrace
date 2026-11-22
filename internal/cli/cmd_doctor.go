// doctor implements the §41 diagnostics command: it inspects the
// installation, configuration, credentials, identity setup, scope, input
// files, database, storage permissions, evidence configuration, network
// readiness, supported protocol status and upgrade state, and returns
// actionable remediation for every failure.
//
// doctor NEVER contacts scan targets: network readiness is judged from local
// configuration and the resolver only, so running doctor is always safe.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/storage"
	"github.com/Lutfifakee-Project/owntrace/internal/version"
)

type check struct {
	Status      string `json:"status"` // PASS|FAIL|WARN
	Name        string `json:"name"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

func doctorCmd() *Command {
	return &Command{
		Name:  "doctor",
		Short: "Validate installation, configuration and readiness",
		Usage: "[--config path] [--json]",
		Long: "Inspects installation, configuration, credential availability, identity probes, scope,\n" +
			"input files, database, storage permissions, evidence configuration, network readiness,\n" +
			"supported protocol status and upgrade state. Every failure carries an actionable fix.\n" +
			"doctor never contacts scan targets.",
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("json", false, "machine-readable output on stdout")
		},
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			asJSON := boolFlag(fs, "json")
			cfgPath := fs.Lookup("config").Value.String()
			checks := runDoctor(cfgPath)
			failed := 0
			for _, c := range checks {
				if c.Status == "FAIL" {
					failed++
				}
			}
			if asJSON {
				out, _ := json.MarshalIndent(checks, "", "  ")
				fmt.Fprintln(s.Out, string(out))
			} else {
				for _, c := range checks {
					fmt.Fprintf(s.Out, "[%s] %s: %s\n", c.Status, c.Name, c.Detail)
					if c.Remediation != "" && c.Status != "PASS" {
						fmt.Fprintf(s.Out, "       fix: %s\n", c.Remediation)
					}
				}
				verdict := "ready to scan"
				if failed > 0 {
					verdict = fmt.Sprintf("%d failed check(s) — resolve them before scanning", failed)
				}
				fmt.Fprintf(s.Out, "\ndoctor: %s\n", verdict)
			}
			if failed > 0 {
				return exitError(ExitConfig)
			}
			return nil
		},
	}
}

// exitError carries an explicit process exit code.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func runDoctor(cfgPath string) []check {
	var checks []check
	add := func(status, name, detail, remediation string) {
		checks = append(checks, check{Status: status, Name: name, Detail: detail, Remediation: remediation})
	}

	// 1. Installation & version.
	add("PASS", "installation", "OWNTRACE "+version.String(), "")

	// 2. Configuration + credentials (loaded once; secret resolution runs here).
	cfg, err := config.Load(cfgPath, filepath.Join(filepath.Dir(cfgPath), "auth.yaml"))
	if err != nil {
		// Fall back to the sibling default auth path resolution used by the CLI.
		cfg, err = config.Load(cfgPath, defaultAuthPath(cfgPath))
	}
	if err != nil {
		add("FAIL", "config", truncateCheck(err.Error(), 240), "run `owntrace init` or fix owntrace.yaml/auth.yaml; validate with `owntrace config validate`")
		add("FAIL", "credentials", "not checked (configuration failed to load)", "")
		add("WARN", "identity-separation", "not checked (configuration failed to load)", "")
		add("FAIL", "scope", "not checked (configuration failed to load)", "")
		add("WARN", "database", "not opened (configuration failed to load)", "")
		return finishChecks(checks)
	}

	// 3. Credentials per profile.
	var credIssues []string
	for _, p := range cfg.Auth.Profiles {
		if p.Name == "" {
			continue
		}
		if p.Token == "" && len(p.Headers) == 0 && len(p.Cookies) == 0 && p.Username == "" {
			credIssues = append(credIssues, p.Name+" has no credentials")
		}
	}
	if len(credIssues) == 0 {
		add("PASS", "credentials", fmt.Sprintf("%d profile(s) carry credentials", len(cfg.Auth.Profiles)), "")
	} else {
		add("FAIL", "credentials", strings.Join(credIssues, "; "),
			"set the referenced {{ env VAR }} variables or edit auth.yaml")
	}

	// 4. Identity separation probes.
	var unprobed []string
	for _, p := range cfg.Auth.Profiles {
		if p.Identity.Endpoint == "" {
			unprobed = append(unprobed, p.Name)
		}
	}
	if len(unprobed) == 0 {
		add("PASS", "identity-separation", "every profile has an identity probe configured", "")
	} else {
		add("WARN", "identity-separation", fmt.Sprintf("no identity probe for: %s — distinctness cannot be verified and cross-account CONFIRMED is blocked for them",
			strings.Join(unprobed, ", ")), "add auth.profiles[].identity (endpoint + distinguishing field)")
	}

	// 5. Scope.
	names := make([]string, 0, len(cfg.Scope.Targets))
	for _, t := range cfg.Scope.Targets {
		names = append(names, t.Host)
	}
	add("PASS", "scope", fmt.Sprintf("%d authorized target(s): %s", len(cfg.Scope.Targets), strings.Join(names, ", ")), "")

	// 6. Input files.
	var missing []string
	for _, f := range append(append([]string{}, cfg.Discovery.HARFiles...), cfg.Discovery.OpenAPIFiles...) {
		if f == "" {
			continue
		}
		if _, serr := os.Stat(expandHome(f)); serr != nil {
			missing = append(missing, f)
		}
	}
	for _, f := range cfg.Workflows.Files {
		if _, serr := os.Stat(expandHome(f)); serr != nil {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		add("PASS", "input-files", fmt.Sprintf("%d discovery/workflow input(s) present", len(cfg.Discovery.HARFiles)+len(cfg.Discovery.OpenAPIFiles)+len(cfg.Workflows.Files)), "")
	} else {
		add("FAIL", "input-files", "missing: "+strings.Join(missing, ", "), "create the files or remove them from the configuration")
	}

	// 7. Database + storage permissions.
	dbPath := filepath.Join(cfg.Session.OutputDir, "owntrace.db")
	if db, derr := storage.Open(dbPath); derr != nil {
		add("FAIL", "database", truncateCheck(derr.Error(), 240), "check the output directory is writable")
	} else {
		_ = db.Close()
		if fi, serr := os.Stat(cfg.Session.OutputDir); serr == nil && fi.Mode().Perm()&0o077 != 0 {
			add("WARN", "storage-permissions", fmt.Sprintf("output dir %s is group/world accessible (%s)", cfg.Session.OutputDir, fi.Mode().Perm()),
				"chmod 700 the output directory — it contains assessment data")
		} else {
			add("PASS", "storage-permissions", fmt.Sprintf("output dir %s permissions are private", cfg.Session.OutputDir), "")
		}
		if fi, serr := os.Stat(dbPath); serr == nil && fi.Mode().Perm()&0o077 != 0 {
			add("WARN", "storage-permissions", fmt.Sprintf("database %s is group/world accessible (%s)", dbPath, fi.Mode().Perm()),
				"chmod 600 the database — it contains evidence and findings")
		}
		add("PASS", "database", fmt.Sprintf("opens and migrates cleanly (schema v%d): %s", storage.SchemaVersion, dbPath), "")
	}

	// 8. Evidence configuration.
	if cfg.Retention.Days > 0 {
		add("PASS", "evidence", fmt.Sprintf("evidence storage enabled; retention %d day(s)", cfg.Retention.Days), "")
	} else {
		add("WARN", "evidence", "retention disabled (data kept indefinitely)", "set retention.days")
	}

	// 9. Network readiness (local only — targets are never contacted).
	if _, lerr := net.LookupHost("localhost"); lerr != nil {
		add("FAIL", "network", "local resolver not functional: "+lerr.Error(), "check the system DNS configuration")
	} else {
		add("PASS", "network", "local resolver functional; no scan targets contacted by doctor", "")
	}

	// 10. Supported protocol status (honest support matrix, §31).
	add("PASS", "protocols", "supported: HTTP/HTTPS REST JSON, HTML crawl, HAR 1.2, OpenAPI 3.x, Swagger 2.0, GraphQL over HTTP", "")
	add("WARN", "protocols", "unsupported adapters (documented): SOAP/WSDL, WebSocket, gRPC/Protobuf — requests to such surfaces report UNSUPPORTED", "see docs/discovery.md for the support matrix")

	// 11. Upgrade state.
	if cfg.Version != config.SchemaVersion {
		add("FAIL", "upgrade", fmt.Sprintf("config schema version %d, binary expects %d", cfg.Version, config.SchemaVersion),
			"update owntrace.yaml `version` field and re-run `owntrace config validate`")
	} else {
		add("PASS", "upgrade", "configuration schema matches this binary", "")
	}

	return finishChecks(checks)
}

func finishChecks(checks []check) []check { return checks }

func truncateCheck(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func defaultAuthPath(cfgPath string) string {
	dir := filepath.Dir(cfgPath)
	if dir == "" {
		return "auth.yaml"
	}
	return filepath.Join(dir, "auth.yaml")
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
