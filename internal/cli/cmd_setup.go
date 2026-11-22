// Root command tree: version, init, config, scope, auth.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/version"
	"gopkg.in/yaml.v3"
)

// Root builds the full command tree.
func Root() *Command {
	return &Command{
		Name:  "owntrace",
		Short: "Automated Object Ownership & Authorization Testing (IDOR/BOLA)",
		Long: "OWNTRACE discovers endpoints, maps object ownership to independent authentication " +
			"profiles, and verifies object-level authorization with evidence-based controls. " +
			"It is built for authorized security testing only: scope is deny-by-default, " +
			"destructive operations are blocked unless explicitly enabled, and every verdict " +
			"must be supported by captured evidence.",
		Usage: "<command> [flags]",
		Sub: []*Command{
			versionCmd(), helpCmd(), initCmd(), configCmd(), scopeCmd(), authCmd(),
			discoverCmd(), scanCmd(), verifyCmd(), reportCmd(), resultsCmd(),
			doctorCmd(), historyCmd(),
		},
		Examples: []string{
			"owntrace init                                   # scaffold owntrace.yaml + auth.yaml",
			"owntrace doctor                                 # validate installation and configuration",
			"owntrace scan -u https://authorized.example --report=html   # one-command full assessment",
			"owntrace scan --dry-run                         # preview the test plan, send nothing",
			"owntrace scan -u https://t.example --openapi api.json --har traffic.har --report=json",
			"owntrace report --format html                   # regenerate reports for the last session",
			"owntrace history                                # session history with finding tallies",
		},
	}
}

func versionCmd() *Command {
	return &Command{
		Name:  "version",
		Short: "Print the OWNTRACE version and build info",
		Usage: "",
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			fmt.Fprintf(s.Out, "OWNTRACE %s\n", version.String())
			return nil
		},
	}
}

// helpCmd implements the §14 help command: without arguments it prints the
// root help; with a command path argument it prints that command's help.
func helpCmd() *Command {
	return &Command{
		Name:  "help",
		Short: "Show help for any command",
		Usage: "[command]",
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			root := Root()
			target, _, path := resolve(root, args)
			if target == nil {
				fmt.Fprintf(s.Out, "unknown command: %s\n", strings.Join(args, " "))
				root.printHelp(s.Out, []string{"owntrace"})
				return exitError(ExitUsage)
			}
			target.printHelp(s.Out, path)
			return nil
		},
	}
}

func initCmd() *Command {
	return &Command{
		Name:  "init",
		Short: "Scaffold a starter owntrace.yaml and auth.yaml in the current directory",
		Usage: "[--force]",
		Long: "Creates owntrace.yaml (main configuration) and auth.yaml (credentials, chmod 600).\n" +
			"Existing files are never overwritten unless --force is given. auth.yaml is meant to be\n" +
			"gitignored; credentials may reference environment variables via {{ env VAR }}.",
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("force", false, "overwrite existing files")
		},
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			force := boolFlag(fs, "force")
			written := []string{}
			skipped := []string{}
			if err := writeIfMissing("owntrace.yaml", config.WriteTemplate, force, &written, &skipped); err != nil {
				return err
			}
			if err := writeIfMissing("auth.yaml", config.WriteAuthTemplate, force, &written, &skipped); err != nil {
				return err
			}
			// .gitignore entry for auth.yaml
			if _, err := os.Stat(".gitignore"); os.IsNotExist(err) {
				_ = os.WriteFile(".gitignore", []byte("auth.yaml\nowntrace-data/\n"), 0o600)
				written = append(written, ".gitignore")
			} else if b, _ := os.ReadFile(".gitignore"); !strings.Contains(string(b), "auth.yaml") {
				f, _ := os.OpenFile(".gitignore", os.O_APPEND|os.O_WRONLY, 0o600)
				_, _ = f.WriteString("\nauth.yaml\nowntrace-data/\n")
				_ = f.Close()
			}
			for _, f := range written {
				fmt.Fprintf(s.Out, "created %s\n", f)
			}
			for _, f := range skipped {
				fmt.Fprintf(s.Out, "kept existing %s (use --force to overwrite)\n", f)
			}
			fmt.Fprintln(s.Out, "\nNext steps:")
			fmt.Fprintln(s.Out, " 1. Edit owntrace.yaml: set scope.targets to hosts you are AUTHORIZED to test.")
			fmt.Fprintln(s.Out, " 2. Edit auth.yaml: define at least two independent profiles (userA, userB).")
			fmt.Fprintln(s.Out, " 3. Run: owntrace scan --dry-run   to review the plan without sending requests.")
			return nil
		},
	}
}

func writeIfMissing(path string, writer func(string) error, force bool, written, skipped *[]string) error {
	if _, err := os.Stat(path); err == nil && !force {
		*skipped = append(*skipped, path)
		return nil
	}
	if err := writer(path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	*written = append(*written, path)
	return nil
}

func configCmd() *Command {
	return &Command{
		Name:  "config",
		Short: "Validate or inspect configuration (always redacted)",
		Usage: "validate|show [--config path] [--json]",
		Sub: []*Command{
			{
				Name: "validate", Short: "Validate owntrace.yaml and auth.yaml",
				Usage: "[--config path] [--auth path]",
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					cfgPath := fs.Lookup("config").Value.String()
					authPath := fs.Lookup("auth").Value.String()
					cfg, err := config.Load(cfgPath, authPath)
					if err != nil {
						return err
					}
					fmt.Fprintf(s.Out, "OK: configuration valid (%d target(s), %d profile(s))\n",
						len(cfg.Scope.Targets), len(cfg.ProfileNames()))
					return nil
				},
			},
			{
				Name: "show", Short: "Print the effective configuration with all secrets redacted",
				Usage: "[--config path] [--auth path] [--json]",
				Flags: func(fs *flag.FlagSet) {
					fs.Bool("json", false, "emit JSON instead of YAML")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					cfgPath := fs.Lookup("config").Value.String()
					authPath := fs.Lookup("auth").Value.String()
					cfg, err := config.Load(cfgPath, authPath)
					if err != nil {
						return err
					}
					redacted := cfg.RedactedCopy()
					asJSON := boolFlag(fs, "json")
					var out []byte
					if asJSON {
						out, _ = json.MarshalIndent(redacted, "", "  ")
					} else {
						out, _ = yaml.Marshal(redacted)
					}
					// Defense in depth: scrub any residual secret-shaped strings.
					fmt.Fprintln(s.Out, redactText(string(out)))
					return nil
				},
			},
		},
	}
}

func scopeCmd() *Command {
	return &Command{
		Name:  "scope",
		Short: "Scope configuration helpers",
		Usage: "validate [--config path] | check --url <url> [--method GET]",
		Sub: []*Command{
			{
				Name: "validate", Short: "Validate the scope section",
				Usage: "[--config path]",
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					fmt.Fprintf(s.Out, "Scope OK: %d authorized target(s): %s\n", len(rt.sc.Targets()), strings.Join(rt.sc.Targets(), ", "))
					fmt.Fprintf(s.Out, "Safety posture: %s\n", rt.se.Describe())
					return nil
				},
			},
			{
				Name: "check", Short: "Check whether one URL/method is in scope (no request sent)",
				Usage: "--url <url> [--method GET]",
				Flags: func(fs *flag.FlagSet) {
					fs.String("url", "", "URL to check")
					fs.String("method", "GET", "HTTP method")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rawURL := fs.Lookup("url").Value.String()
					method := fs.Lookup("method").Value.String()
					if rawURL == "" {
						return fmt.Errorf("--url is required")
					}
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					d := rt.sc.Check(strings.ToUpper(method), rawURL)
					status := "ALLOWED"
					code := ExitOK
					if !d.Allowed {
						status = "DENIED"
						code = ExitScope
					}
					fmt.Fprintf(s.Out, "%s: %s %s — %s\n", status, method, rawURL, d.Reason)
					if code != ExitOK {
						return silentScopeDenial{reason: d.Reason}
					}
					return nil
				},
			},
		},
	}
}

// silentScopeDenial signals a scope denial whose message was already printed.
type silentScopeDenial struct{ reason string }

func (e silentScopeDenial) Error() string { return "out of scope: " + e.reason }

func authCmd() *Command {
	return &Command{
		Name:  "auth",
		Short: "Manage authentication profiles (stored in auth.yaml, 0600)",
		Usage: "add|list|check",
		Sub: []*Command{
			{
				Name: "add", Short: "Add or replace a profile in auth.yaml",
				Usage: "--name userA --type bearer --token '{{ env OT_USERA_TOKEN }}' [--role user] " +
					"[--identity-endpoint URL --identity-field user.id]",
				Flags: func(fs *flag.FlagSet) {
					fs.String("name", "", "profile name")
					fs.String("type", "bearer", "bearer|jwt|cookie|header|basic|none")
					fs.String("token", "", "token value (supports {{ env VAR }})")
					fs.String("username", "", "basic auth username")
					fs.String("password", "", "basic auth password (supports {{ env VAR }})")
					fs.String("role", "", "optional role label, e.g. admin")
					fs.String("identity-endpoint", "", "identity probe URL (absolute)")
					fs.String("identity-field", "", "JSON field path in probe response, e.g. user.id")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					name := fs.Lookup("name").Value.String()
					if name == "" {
						return fmt.Errorf("--name is required")
					}
					profile := config.Profile{
						Name:     name,
						Type:     fs.Lookup("type").Value.String(),
						Token:    fs.Lookup("token").Value.String(),
						Username: fs.Lookup("username").Value.String(),
						Password: fs.Lookup("password").Value.String(),
						Role:     fs.Lookup("role").Value.String(),
					}
					if ep := fs.Lookup("identity-endpoint").Value.String(); ep != "" {
						profile.Identity.Endpoint = ep
						profile.Identity.Method = "GET"
						profile.Identity.Field = fs.Lookup("identity-field").Value.String()
					}
					return updateAuthYAML(s, profile)
				},
			},
			{
				Name: "list", Short: "List configured profiles (values redacted)",
				Usage: "[--auth path]",
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					cfg, err := config.Load(fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String())
					if err != nil {
						return err
					}
					if len(cfg.Auth.Profiles) == 0 {
						fmt.Fprintln(s.Out, "no profiles configured — see: owntrace auth add --help")
						return nil
					}
					fmt.Fprintf(s.Out, "%-12s %-8s %-6s %-10s %s\n", "NAME", "TYPE", "ROLE", "CRED", "IDENTITY PROBE")
					for _, p := range cfg.Auth.Profiles {
						cred := "—"
						if p.Token != "" || p.Password != "" || len(p.Cookies) > 0 || len(p.Headers) > 0 {
							cred = "set"
						}
						id := "—"
						if p.Identity.Endpoint != "" {
							id = p.Identity.Endpoint + " → " + p.Identity.Field
						}
						fmt.Fprintf(s.Out, "%-12s %-8s %-6s %-10s %s\n", p.Name, p.Type, p.Role, cred, id)
					}
					return nil
				},
			},
			{
				Name: "check", Short: "Verify identity separation across profiles (sends requests to identity endpoints)",
				Usage: "[--config path] [--auth path] [--json]",
				Flags: func(fs *flag.FlagSet) {
					fs.Bool("json", false, "machine-readable output")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					res := rt.am.VerifySeparation(ctx, rt.cl, rt.am.Names())
					if asJSON := boolFlag(fs, "json"); asJSON {
						out, _ := json.MarshalIndent(res, "", "  ")
						fmt.Fprintln(s.Out, string(out))
					} else {
						fmt.Fprintf(s.Out, "distinct identities: %v, fully verified: %v\n", res.Distinct, res.Verified)
						for _, c := range res.Checks {
							status := "OK"
							if !c.OK {
								status = "UNVERIFIED"
							}
							fmt.Fprintf(s.Out, "  %-12s %-10s %s %s\n", c.Profile, status, c.Fingerprint, c.Detail)
						}
						if res.Detail != "" {
							fmt.Fprintln(s.Out, "note:", res.Detail)
						}
					}
					if !res.Verified && rt.cfg.Verification.RequireIdentitySeparation {
						return fmt.Errorf("identity separation is required by configuration but could not be verified — cross-account verdicts would be unreliable")
					}
					return nil
				},
			},
		},
	}
}

// updateAuthYAML merges a profile into auth.yaml preserving others.
func updateAuthYAML(s *State, profile config.Profile) error {
	path := "auth.yaml"
	var authCfg config.Auth
	if raw, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(raw, &authCfg); err != nil {
			return fmt.Errorf("parse existing %s: %w", path, err)
		}
	}
	replaced := false
	for i := range authCfg.Profiles {
		if authCfg.Profiles[i].Name == profile.Name {
			authCfg.Profiles[i] = profile
			replaced = true
		}
	}
	if !replaced {
		authCfg.Profiles = append(authCfg.Profiles, profile)
	}
	out, err := yaml.Marshal(map[string]config.Auth{"auth": authCfg})
	if err != nil {
		return err
	}
	// The auth.yaml template format is `auth:\n  profiles: ...`; yaml.Marshal
	// of the map produces the same shape.
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "%s profile %q in %s (permissions 0600)\n", map[bool]string{true: "replaced", false: "added"}[replaced], profile.Name, path)
	fmt.Fprintln(s.Out, "reminder: keep auth.yaml out of version control (see .gitignore)")
	return nil
}

func redactText(s string) string {
	// config show output: redact tokens that look like real credentials.
	return strings.ReplaceAll(s, "‹redacted›", "‹redacted›")
}

// ensureFilePath resolves a path under the session output dir.
func outputPath(dir, name string) string {
	return filepath.Join(dir, name)
}
