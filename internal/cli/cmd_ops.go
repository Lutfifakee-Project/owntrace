// Operational commands: discover, scan, verify, report, results.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/discovery"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/report"
	"github.com/Lutfifakee-Project/owntrace/internal/scan"
	"github.com/Lutfifakee-Project/owntrace/internal/storage"
	"github.com/Lutfifakee-Project/owntrace/internal/verification"
)

func discoverCmd() *Command {
	return &Command{
		Name:  "discover",
		Short: "Run discovery sources and list in-scope endpoints (no authorization testing)",
		Usage: "<subcommand> | --target URL",
		Long: "Discovery builds the endpoint inventory from configured sources. Every endpoint is\n" +
			"scope-filtered before display; nothing is tested here. Use `scan` for authorization testing.\n" +
			"With --target the URL declares the authorized scope for this run and seeds discovery.",
		Flags: func(fs *flag.FlagSet) {
			targets := &repeatFlag{}
			fs.Var(targets, "target", "authorized target base URL; declares scope for this run and seeds discovery (alias: -u)")
			fs.Var(targets, "u", "alias of --target")
		},
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			if len(flagValues(fs, "target")) == 0 {
				fs.Usage()
				return nil
			}
			rt, err := bootstrapOverlay(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log, discoverOverlay(fsAdapter{fs}))
			if err != nil {
				return err
			}
			defer rt.close()
			res, err := discovery.Run(ctx, rt.cfg, rt.cl, rt.sc, s.Log)
			if err != nil {
				return err
			}
			return printEndpoints(s, res)
		},
		Sub: []*Command{
			{
				Name: "urls", Short: "Discover from explicit seed URLs",
				Usage: "[--url URL]... [--config path]",
				Flags: func(fs *flag.FlagSet) {
					fs.Var(&repeatFlag{}, "url", "seed URL (repeatable)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					seeds := fs.Lookup("url").Value.(flag.Value).(*repeatFlag).values
					if len(rt.cfg.Discovery.Seeds) == 0 && len(seeds) == 0 {
						return fmt.Errorf("no seeds: pass --url or set discovery.seeds in config")
					}
					rt.cfg.Discovery.Seeds = append(rt.cfg.Discovery.Seeds, seeds...)
					rt.cfg.Discovery.Sources = []string{"url"}
					res, err := discovery.Run(ctx, rt.cfg, rt.cl, rt.sc, s.Log)
					if err != nil {
						return err
					}
					return printEndpoints(s, res)
				},
			},
			{
				Name: "har", Short: "Discover from HAR 1.2 files",
				Usage: "[--file path]... [--config path]",
				Flags: func(fs *flag.FlagSet) {
					fs.Var(&repeatFlag{}, "file", "HAR file (repeatable)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					files := fs.Lookup("file").Value.(flag.Value).(*repeatFlag).values
					if len(files) == 0 {
						files = rt.cfg.Discovery.HARFiles
					}
					if len(files) == 0 {
						return fmt.Errorf("no HAR files: pass --file or set discovery.har_files")
					}
					rt.cfg.Discovery.HARFiles = files
					rt.cfg.Discovery.Sources = []string{"har"}
					res, err := discovery.Run(ctx, rt.cfg, rt.cl, rt.sc, s.Log)
					if err != nil {
						return err
					}
					return printEndpoints(s, res)
				},
			},
			{
				Name: "openapi", Short: "Discover from OpenAPI 3.x / Swagger 2.x documents",
				Usage: "[--file path]... [--config path]",
				Flags: func(fs *flag.FlagSet) {
					fs.Var(&repeatFlag{}, "file", "spec file (repeatable)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					files := fs.Lookup("file").Value.(flag.Value).(*repeatFlag).values
					if len(files) == 0 {
						files = rt.cfg.Discovery.OpenAPIFiles
					}
					if len(files) == 0 {
						return fmt.Errorf("no spec files: pass --file or set discovery.openapi_files")
					}
					rt.cfg.Discovery.OpenAPIFiles = files
					rt.cfg.Discovery.Sources = []string{"openapi"}
					res, err := discovery.Run(ctx, rt.cfg, rt.cl, rt.sc, s.Log)
					if err != nil {
						return err
					}
					return printEndpoints(s, res)
				},
			},
			{
				Name: "crawl", Short: "Crawl HTML/JS from seed pages (GET only, scope-bound)",
				Usage: "[--seed URL]... [--config path]",
				Flags: func(fs *flag.FlagSet) {
					fs.Var(&repeatFlag{}, "seed", "crawl seed (repeatable)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					seeds := fs.Lookup("seed").Value.(flag.Value).(*repeatFlag).values
					if len(seeds) == 0 {
						seeds = rt.cfg.Discovery.CrawlSeeds
					}
					if len(seeds) == 0 {
						return fmt.Errorf("no crawl seeds: pass --seed or set discovery.crawl_seeds")
					}
					rt.cfg.Discovery.CrawlSeeds = seeds
					rt.cfg.Discovery.Sources = []string{"crawl"}
					res, err := discovery.Run(ctx, rt.cfg, rt.cl, rt.sc, s.Log)
					if err != nil {
						return err
					}
					return printEndpoints(s, res)
				},
			},
		},
	}
}

func printEndpoints(s *State, res *discovery.Result) error {
	fmt.Fprintf(s.Out, "discovered %d in-scope endpoint(s):\n\n", res.Endpoints.Len())
	fmt.Fprintf(s.Out, "%-7s %-40s %-8s %-6s %s\n", "METHOD", "URL", "AUTH", "FLAGS", "SOURCE")
	for _, ep := range res.Endpoints.List() {
		flags := ""
		if ep.Adminish {
			flags += "A"
		}
		if ep.Collection {
			flags += "C"
		}
		src := ""
		if len(ep.Sources) > 0 {
			src = string(ep.Sources[0].Kind)
		}
		fmt.Fprintf(s.Out, "%-7s %-40s %-8s %-6s %s\n", ep.Method, redact.URL(ep.URL()), ep.Auth, flags, src)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(s.Out, "note: %s\n", n)
	}
	return nil
}

func scanCmd() *Command {
	return &Command{
		Name:  "scan",
		Short: "Run the full authorization testing pipeline",
		Usage: "[--config path] [-u|--target URL] [--report=html] [--openapi FILE] [--har FILE]\n" +
			"                         [--workflow FILE] [--profile NAME] [--list FILE] [--scope FILE]\n" +
			"                         [--output DIR] [--no-discover] [--dry-run] [--json]",
		Long: "Executes: discovery → identity separation check → ownership mapping → cross-account\n" +
			"authorization testing → deterministic verification → evidence capture → persisted\n" +
			"findings → reports. This is the primary command: a complete assessment runs with\n" +
			"one invocation. A safety summary is printed before active testing. Interrupt at\n" +
			"any time (Ctrl-C); completed controls stay in the session DB.\n" +
			"Exit code 5 signals CONFIRMED findings (useful for CI).",
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("dry-run", false, "build and print the plan without sending testing requests")
			fs.Bool("json", false, "machine-readable summary on stdout")
			targets := &repeatFlag{}
			fs.Var(targets, "target", "authorized target base URL (repeatable); path prefix narrows scope; alias: -u")
			fs.Var(targets, "u", "alias of --target")
			fs.Var(&repeatFlag{}, "openapi", "OpenAPI 3.x / Swagger 2.0 file to ingest (repeatable)")
			fs.Var(&repeatFlag{}, "har", "HAR 1.2 traffic file to ingest (repeatable)")
			fs.Var(&repeatFlag{}, "workflow", "application workflow file (repeatable)")
			fs.Var(&repeatFlag{}, "profile", "restrict testing to these auth profiles (repeatable)")
			fs.Var(&repeatFlag{}, "list", "file with seed URLs, one per line (alias: -l)")
			fs.Var(&repeatFlag{}, "l", "alias of --list")
			fs.String("report", "", "report formats, comma-separated: html,json,md,csv (overrides config)")
			fs.String("output", "", "output directory override")
			fs.String("scope", "", "scope-only YAML file replacing the configured scope")
			fs.Bool("no-discover", false, "reuse the most recent completed session's inventory instead of running discovery (rejects missing, stale or scope-incompatible inventories)")
		},
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			overlay := scanOverlay(fsAdapter{fs})
			rt, err := bootstrapOverlay(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log, overlay)
			if err != nil {
				return err
			}
			defer rt.close()
			dryRun := boolFlag(fs, "dry-run")
			asJSON := boolFlag(fs, "json")

			if dryRun {
				_ = rt.db.Audit("", "info", "dry_run", "plan only")
			}
			fmt.Fprintln(s.Out, "OWNTRACE — testing summary")
			fmt.Fprintf(s.Out, "  scope:      %s\n", strings.Join(rt.sc.Targets(), ", "))
			fmt.Fprintf(s.Out, "  safety:     %s\n", rt.se.Describe())
			fmt.Fprintf(s.Out, "  profiles:   %s\n", strings.Join(rt.am.Names(), ", "))
			fmt.Fprintf(s.Out, "  dry-run:    %v\n", dryRun)
			if dryRun {
				fmt.Fprintln(s.Out, "  (dry-run: discovery + ownership mapping only; verification requests are NOT sent)")
			} else {
				fmt.Fprintln(s.Out, "  starting active testing — press Ctrl-C to stop gracefully")
			}
			fmt.Fprintln(s.Out, "")

			runner := &scan.Runner{
				Cfg: rt.cfg, Scope: rt.sc, Client: rt.cl, Auth: rt.am,
				Log: s.Log, DB: rt.db, Evid: rt.ev, Verif: rt.ve,
			}
			sum, err := runner.Run(ctx, dryRun)
			if err != nil {
				printSummary(s, sum, asJSON)
				return err
			}
			printSummary(s, sum, asJSON)

			if !dryRun {
				// Auto-generate configured reports for the session.
				repErr := generateReports(s, rt, sum.SessionID)
				if repErr != nil {
					s.Log.Warnf("report generation: %v", repErr)
				}
			}
			if confirmed := sum.Findings[string(finding.StateConfirmed)]; confirmed > 0 {
				return findingsExit{confirmed}
			}
			return nil
		},
	}
}

type findingsExit struct{ confirmed int }

func (e findingsExit) Error() string {
	return fmt.Sprintf("%d CONFIRMED finding(s) recorded", e.confirmed)
}

func printSummary(s *State, sum *scan.Summary, asJSON bool) {
	if sum == nil {
		return
	}
	if asJSON {
		out, _ := json.MarshalIndent(sum, "", "  ")
		fmt.Fprintln(s.Out, string(out))
		return
	}
	fmt.Fprintln(s.Out, "Session:", sum.SessionID)
	fmt.Fprintf(s.Out, "Endpoints: %d · Objects: %d · Requests: %d\n", sum.Endpoints, sum.Objects, sum.Requests)
	fmt.Fprintf(s.Out, "Identity separation verified: %v\n", sum.IdentityOK)
	fmt.Fprintf(s.Out, "Authorization coverage: %d/%d planned check(s) executed, %d safety-skipped\n",
		sum.ChecksExecuted, sum.ChecksPlanned, sum.SafetySkipped)
	for _, n := range sum.OwnershipNotes {
		fmt.Fprintf(s.Out, "ownership: %s\n", n)
	}
	fmt.Fprintln(s.Out, "Findings by state:")
	for _, state := range []string{"CONFIRMED", "SUSPECTED", "INCONCLUSIVE", "REJECTED", "ERROR"} {
		if n := sum.Findings[state]; n > 0 {
			fmt.Fprintf(s.Out, "  %-14s %d\n", state, n)
		}
	}
	for _, n := range sum.Notes {
		fmt.Fprintln(s.Out, "note:", n)
	}
}

func verifyCmd() *Command {
	return &Command{
		Name:  "verify",
		Short: "Re-run verification controls for stored findings",
		Usage: "[--finding ID] [--state SUSPECTED] [--config path]",
		Long: "Re-executes the verification battery against the original test coordinates and updates\n" +
			"the stored findings (previous states remain in the transition history).",
		Flags: func(fs *flag.FlagSet) {
			fs.String("finding", "", "re-verify one finding by ID")
			fs.String("state", "SUSPECTED", "re-verify all findings in this state (SUSPECTED|INCONCLUSIVE|CONFIRMED|ALL)")
		},
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
			if err != nil {
				return err
			}
			defer rt.close()
			one := fs.Lookup("finding").Value.String()
			state := fs.Lookup("state").Value.String()

			var targets []*finding.Finding
			if one != "" {
				f, err := loadFinding(rt, one)
				if err != nil {
					return err
				}
				targets = []*finding.Finding{f}
			} else {
				st := ""
				if !strings.EqualFold(state, "ALL") {
					st = strings.ToUpper(state)
				}
				targets, err = rt.db.ListFindings(rt.cfg.Session.Name, st)
				if err != nil {
					return err
				}
				if len(targets) == 0 {
					return fmt.Errorf("no findings matching state %q — run `owntrace results list` to see stored findings", state)
				}
			}
			fmt.Fprintf(s.Out, "re-verifying %d finding(s)\n", len(targets))
			for _, f := range targets {
				item := verification.TestItem{
					URL:        f.URL,
					Method:     f.Method,
					Resource:   f.Resource,
					Identifier: f.Identifier,
					Owner:      f.OwnerProfile,
					OwnerState: ownership.State(f.OwnerState),
					Category:   f.Category,
					EndpointID: f.EndpointID,
				}
				nf := rt.ve.VerifyItem(ctx, item)
				fmt.Fprintf(s.Out, "  %s → %s (was %s): %s\n", nf.ID, nf.State, f.State, nf.Reason)
			}
			return nil
		},
	}
}

func reportCmd() *Command {
	return &Command{
		Name:  "report",
		Short: "Generate reports for a session",
		Usage: "[--session ID] [--formats json,markdown,html,csv] [--out dir] [--config path]",
		Flags: func(fs *flag.FlagSet) {
			fs.String("session", "", "session ID (default: latest)")
			fs.String("formats", "", "comma list overriding config: json,markdown,html,csv")
			fs.String("format", "", "single format for this run: json|markdown|md|html|csv (convenience alias)")
			fs.String("out", "", "output directory (default: <output_dir>/reports)")
		},
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
			if err != nil {
				return err
			}
			defer rt.close()
			sessID := fs.Lookup("session").Value.String()
			if sessID == "" {
				sessID, err = rt.db.LatestSessionID()
				if err != nil {
					return fmt.Errorf("no sessions found; run a scan first")
				}
			}
			if formats := fs.Lookup("formats").Value.String(); formats != "" {
				rt.cfg.Report.Formats = strings.Split(formats, ",")
			} else if format := strFlag(fs, "format"); format != "" {
				rt.cfg.Report.Formats = []string{format}
			} else if format := strFlag(fs, "format"); format != "" {
				rt.cfg.Report.Formats = []string{format}
			}
			if out := fs.Lookup("out").Value.String(); out != "" {
				rt.cfg.Session.OutputDir = out
			}
			return generateReports(s, rt, sessID)
		},
	}
}

func generateReports(s *State, rt *runtime, sessionID string) error {
	col := &report.Collector{DB: rt.db}
	data, err := col.Collect(sessionID, rt.cfg.Report.Title, rt.cfg)
	if err != nil {
		return err
	}
	outDir := filepath.Join(rt.cfg.Session.OutputDir, "reports")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	written := []string{}
	for _, format := range rt.cfg.Report.Formats {
		var (
			content []byte
			name    string
		)
		switch format {
		case "json":
			content, err = data.JSON()
			name = "report.json"
		case "markdown", "md":
			content = data.Markdown()
			name = "report.md"
		case "html":
			content = data.HTML()
			name = "report.html"
		case "csv":
			content, err = data.CSV()
			name = "findings.csv"
		default:
			continue
		}
		if err != nil {
			return fmt.Errorf("render %s: %w", format, err)
		}
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return err
		}
		written = append(written, path)
	}
	for _, p := range written {
		fmt.Fprintf(s.Out, "report written: %s\n", p)
	}
	return nil
}

func resultsCmd() *Command {
	return &Command{
		Name:  "results",
		Short: "List and inspect stored findings and evidence",
		Usage: "list|show|sessions|head|integrity|export|cleanup",
		Sub: []*Command{
			{
				Name: "sessions", Short: "List scan sessions",
				Usage: "[--config path]",
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					sessions, err := rt.db.ListSessions()
					if err != nil {
						return err
					}
					for _, sess := range sessions {
						fmt.Fprintf(s.Out, "%s  %-10s %-24s %s→%s\n", sess.ID, sess.Status, sess.Name, sess.StartedAt, sess.FinishedAt)
					}
					return nil
				},
			},
			{
				Name: "list", Short: "List findings of the latest (or --session) run",
				Usage: "[--session ID] [--state STATE] [--json] [--config path]",
				Flags: func(fs *flag.FlagSet) {
					fs.String("session", "", "session ID (default: latest)")
					fs.String("state", "", "filter by state")
					fs.Bool("json", false, "machine-readable output")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					sessID := fs.Lookup("session").Value.String()
					if sessID == "" {
						if sessID, err = rt.db.LatestSessionID(); err != nil {
							return err
						}
					}
					fsCfg, _ := rt.db.FindingCounts(sessID)
					findings, err := rt.db.ListFindings(sessID, fs.Lookup("state").Value.String())
					if err != nil {
						return err
					}
					if asJSON := boolFlag(fs, "json"); asJSON {
						out, _ := json.MarshalIndent(map[string]any{"session": sessID, "counts": fsCfg, "findings": findings}, "", "  ")
						// URLs are stored raw locally; redact for stdout safety.
						fmt.Fprintln(s.Out, redactJSONText(string(out)))
						return nil
					}
					fmt.Fprintf(s.Out, "session %s — %s\n\n", sessID, countsText(fsCfg))
					fmt.Fprintf(s.Out, "%-10s %-12s %-34s %-42s %s\n", "STATE", "CATEGORY", "FINDING", "ENDPOINT", "ID")
					for _, f := range findings {
						title := f.Title
						if len(title) > 33 {
							title = title[:30] + "…"
						}
						url := redact.URL(f.URL)
						if len(url) > 41 {
							url = url[:38] + "…"
						}
						fmt.Fprintf(s.Out, "%-10s %-12s %-34s %-42s %s\n", f.State, f.Category, title, url, f.ID)
					}
					return nil
				},
			},
			{
				Name: "show", Short: "Show one finding with its evidence and integrity hashes",
				Usage: "--finding ID [--config path]",
				Flags: func(fs *flag.FlagSet) {
					fs.String("finding", "", "finding ID")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					id := fs.Lookup("finding").Value.String()
					if id == "" {
						return fmt.Errorf("--finding is required")
					}
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					f, err := loadFinding(rt, id)
					if err != nil {
						return err
					}
					out, _ := json.MarshalIndent(f, "", "  ")
					fmt.Fprintln(s.Out, redactJSONText(string(out)))
					recs, err := rt.db.GetEvidence(f.ID)
					if err != nil {
						return err
					}
					for _, r := range recs {
						status := "OK"
						if err := r.Verify(); err != nil {
							status = "TAMPERED"
						}
						fmt.Fprintf(s.Out, "evidence %s [%s] integrity=%s sha256=%s\n", r.ID, r.Kind, status, shortHash(r.SHA256))
					}
					return nil
				},
			},
			{
				Name: "head", Short: "Print the trusted evidence-chain head checkpoint for external anchoring",
				Usage: "[--session ID] [--config path]",
				Long: "Prints the per-session evidence chain head as an anchorable checkpoint line (§35).\n" +
					"Copy the checkpoint to external trusted storage (ticket, log, notary).\n" +
					"Later `results integrity --anchored-head <sha>` detects a full-chain rewrite\n" +
					"even when every per-record hash was recomputed by the attacker.",
				Flags: func(fs *flag.FlagSet) {
					fs.String("session", "", "session ID (default: latest)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					sessID := fs.Lookup("session").Value.String()
					if sessID == "" {
						sessID, err = rt.db.LatestSessionID()
						if err != nil {
							return fmt.Errorf("no sessions found; run a scan first")
						}
					}
					head, records, err := rt.db.EvidenceCheckpoint(sessID)
					if err != nil {
						return err
					}
					if head == "" {
						return fmt.Errorf("session %s has no evidence records", sessID)
					}
					fmt.Fprintf(s.Out, "OWNTRACE-EVIDENCE-HEAD session=%s head=%s records=%d\n", sessID, head, records)
					fmt.Fprintf(s.Out, "anchor this checkpoint externally; verify later with: owntrace results integrity --anchored-head %s --session %s\n", head, sessID)
					return nil
				},
			},
			{
				Name: "integrity", Short: "Verify SHA-256 integrity of ALL stored evidence",
				Usage: "[--anchored-head SHA256] [--session ID] [--config path]",
				Flags: func(fs *flag.FlagSet) {
					fs.String("anchored-head", "", "externally anchored chain head (full-chain-rewrite detection)")
					fs.String("session", "", "session for the anchored-head comparison (default: latest)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					checked, failed, errs, err := rt.db.VerifyAllEvidence()
					if err != nil {
						return err
					}
					fmt.Fprintf(s.Out, "evidence records checked: %d, failed: %d\n", checked, failed)
					for _, e := range errs {
						fmt.Fprintln(s.Out, "  ", e)
					}
					if failed > 0 {
						return fmt.Errorf("evidence integrity failures detected")
					}
					if anchored := fs.Lookup("anchored-head").Value.String(); anchored != "" {
						sessID := fs.Lookup("session").Value.String()
						if sessID == "" {
							sessID, err = rt.db.LatestSessionID()
							if err != nil {
								return fmt.Errorf("no sessions found; run a scan first")
							}
						}
						if _, _, aerr := rt.db.VerifyAgainstHead(sessID, anchored); aerr != nil {
							return aerr
						}
						fmt.Fprintf(s.Out, "anchored head MATCH: session %s unchanged since checkpoint\n", sessID)
					}
					return nil
				},
			},
			{
				Name: "cleanup", Short: "Delete sessions older than the configured retention window",
				Usage: "[--config path]",
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					n, err := rt.db.Cleanup(rt.cfg.Retention.Days)
					if err != nil {
						return err
					}
					fmt.Fprintf(s.Out, "removed %d session(s) older than %d day(s)\n", n, rt.cfg.Retention.Days)
					return nil
				},
			},
			{
				Name: "export", Short: "Export a session bundle (evidence-verified JSON)",
				Usage: "[--session ID] --out FILE [--config path]",
				Long: "Exports one session (findings, objects, endpoints, evidence, audit) as a JSON\n" +
					"bundle. The session's evidence hashes and chain are verified BEFORE export; a\n" +
					"tampered session is refused.",
				Flags: func(fs *flag.FlagSet) {
					fs.String("session", "", "session ID (default: latest)")
					fs.String("out", "", "output bundle file (required)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					out := strFlag(fs, "out")
					if out == "" {
						return fmt.Errorf("--out FILE is required")
					}
					sessID := strFlag(fs, "session")
					if sessID == "" {
						if sessID, err = rt.db.LatestSessionID(); err != nil {
							return fmt.Errorf("no sessions found; run a scan first")
						}
					}
					data, err := rt.db.ExportBundle(sessID)
					if err != nil {
						return err
					}
					if err := os.WriteFile(out, data, 0o600); err != nil {
						return fmt.Errorf("write bundle %s: %w", out, err)
					}
					var b storage.Bundle
					_ = json.Unmarshal(data, &b)
					fmt.Fprintf(s.Out, "exported session %s → %s (%d findings, %d evidence records)\n",
						sessID, out, len(b.Findings), len(b.Evidence))
					return nil
				},
			},
			{
				Name: "import", Short: "Import a session bundle as a new session",
				Usage: "--file FILE [--config path]",
				Long: "Imports a session bundle. Evidence payloads and hash chains are verified BEFORE\n" +
					"insertion; a tampered or corrupted bundle is refused. Identifiers are remapped\n" +
					"so re-importing the same bundle is safe.",
				Flags: func(fs *flag.FlagSet) {
					fs.String("file", "", "bundle file (required)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					file := strFlag(fs, "file")
					if file == "" {
						return fmt.Errorf("--file FILE is required")
					}
					data, err := os.ReadFile(file)
					if err != nil {
						return fmt.Errorf("read bundle: %w", err)
					}
					newID, counts, err := rt.db.ImportBundle(data)
					if err != nil {
						return err
					}
					fmt.Fprintf(s.Out, "imported as session %s (findings=%d, evidence=%d, objects=%d, endpoints=%d)\n",
						newID, counts["findings"], counts["evidence"], counts["objects"], counts["endpoints"])
					return nil
				},
			},
			{
				Name: "backup", Short: "Write a consistent snapshot of the database",
				Usage: "--out FILE [--config path]",
				Flags: func(fs *flag.FlagSet) {
					fs.String("out", "", "snapshot file (required)")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
					if err != nil {
						return err
					}
					defer rt.close()
					out := strFlag(fs, "out")
					if out == "" {
						return fmt.Errorf("--out FILE is required")
					}
					if err := rt.db.Backup(out); err != nil {
						return err
					}
					fmt.Fprintf(s.Out, "database snapshot written to %s (0600)\n", out)
					return nil
				},
			},
			{
				Name: "restore", Short: "Replace the database with a verified snapshot",
				Usage: "--file FILE [--force] [--config path]",
				Long: "Restores a database snapshot. The file is validated on a scratch copy (schema\n" +
					"version + integrity_check) BEFORE replacement; the current database is kept as\n" +
					"a timestamped .pre-restore backup next to it. Requires --force.",
				Flags: func(fs *flag.FlagSet) {
					fs.String("file", "", "snapshot file (required)")
					fs.Bool("force", false, "confirm the destructive replacement")
				},
				Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
					file := strFlag(fs, "file")
					if file == "" {
						return fmt.Errorf("--file FILE is required")
					}
					if !boolFlag(fs, "force") {
						return fmt.Errorf("restore replaces the live database — pass --force to confirm")
					}
					cfg, err := config.Load(fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String())
					if err != nil {
						return err
					}
					dbPath := filepath.Join(cfg.Session.OutputDir, "owntrace.db")
					// Validate the snapshot on a scratch copy (never open the
					// live database while restoring).
					scratch := dbPath + ".restore-check"
					data, err := os.ReadFile(file)
					if err != nil {
						return fmt.Errorf("read snapshot: %w", err)
					}
					if err := os.WriteFile(scratch, data, 0o600); err != nil {
						return err
					}
					check, err := storage.Open(scratch)
					if err != nil {
						_ = os.Remove(scratch)
						return fmt.Errorf("snapshot is not a valid OWNTRACE database: %w", err)
					}
					if err := check.IntegrityCheck(); err != nil {
						_ = check.Close()
						_ = os.Remove(scratch)
						return fmt.Errorf("snapshot failed integrity check: %w", err)
					}
					_ = check.Close()
					_ = os.Remove(scratch)
					// Keep the current database as a rollback copy.
					if _, err := os.Stat(dbPath); err == nil {
						bak := dbPath + fmt.Sprintf(".pre-restore-%s", time.Now().UTC().Format("20060102-150405"))
						if err := os.Rename(dbPath, bak); err != nil {
							return fmt.Errorf("preserve current database: %w", err)
						}
						fmt.Fprintf(s.Out, "previous database preserved as %s\n", bak)
					}
					if err := os.WriteFile(dbPath, data, 0o600); err != nil {
						return err
					}
					fmt.Fprintf(s.Out, "database restored from %s\n", file)
					return nil
				},
			},
		},
	}
}

func loadFinding(rt *runtime, id string) (*finding.Finding, error) {
	// Find across all sessions (IDs are unique).
	sessions, err := rt.db.ListSessions()
	if err != nil {
		return nil, err
	}
	for _, sess := range sessions {
		fs, err := rt.db.ListFindings(sess.ID, "")
		if err != nil {
			continue
		}
		for _, f := range fs {
			if f.ID == id {
				return f, nil
			}
		}
	}
	return nil, fmt.Errorf("finding %s not found", id)
}

func countsText(counts map[string]int) string {
	var parts []string
	for _, state := range []string{"CONFIRMED", "SUSPECTED", "INCONCLUSIVE", "REJECTED", "ERROR"} {
		if n := counts[state]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", state, n))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}

func redactJSONText(s string) string {
	// Redact any secret-shaped substrings that might have survived into JSON
	// dumps of locally stored (raw) findings before printing to stdout.
	return redact.Text(s)
}

// repeatFlag collects repeated flag values.
type repeatFlag struct{ values []string }

func (r *repeatFlag) String() string { return strings.Join(r.values, ",") }
func (r *repeatFlag) Set(v string) error {
	r.values = append(r.values, v)
	return nil
}
