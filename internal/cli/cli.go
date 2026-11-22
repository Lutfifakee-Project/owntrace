// Package cli implements the OWNTRACE command-line interface: a small
// dependency-free command framework with help, examples, predictable exit
// codes and machine-readable output.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/safety"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
	"github.com/Lutfifakee-Project/owntrace/internal/storage"
	"github.com/Lutfifakee-Project/owntrace/internal/verification"
)

// Exit codes (documented in docs/cli.md).
const (
	ExitOK            = 0
	ExitUsage         = 1
	ExitConfig        = 2
	ExitScope         = 3
	ExitRuntime       = 4
	ExitFindingsFound = 5
)

// Command is one CLI (sub)command.
type Command struct {
	Name     string
	Short    string
	Usage    string // argument synopsis after the command name
	Long     string
	Examples []string
	Flags    func(fs *flag.FlagSet)
	Run      func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error
	Sub      []*Command
}

// State carries shared runtime objects for command execution.
type State struct {
	Out io.Writer // stdout
	Log *logger.Logger
}

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log := logger.New(logger.LevelInfo)
	st := &State{Out: stdout, Log: log}

	root := Root()
	cmd, remaining, path := resolve(root, args)
	if cmd == nil {
		fmt.Fprintln(stderr, "unknown command:", strings.Join(args, " "))
		root.printHelp(stderr, []string{"owntrace"})
		return ExitUsage
	}

	fs := flag.NewFlagSet(strings.Join(path, " "), flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { cmd.printHelp(stderr, path) }
	var cfgPath, authPath, logLevel string
	var quiet bool
	fs.StringVar(&cfgPath, "config", "./owntrace.yaml", "path to owntrace.yaml")
	fs.StringVar(&authPath, "auth", "./auth.yaml", "path to auth.yaml (credentials)")
	fs.StringVar(&logLevel, "log-level", "info", "log level: debug|info|warn|error")
	fs.BoolVar(&quiet, "quiet", false, "suppress log output on stderr")
	// register -h/--help
	showHelp := fs.Bool("help", false, "show help")
	if cmd.Flags != nil {
		cmd.Flags(fs)
	}
	if err := fs.Parse(remaining); err != nil {
		return ExitUsage
	}
	if *showHelp {
		cmd.printHelp(stdout, path)
		return ExitOK
	}
	log = logger.New(logger.ParseLevel(logLevel))
	log.SetQuiet(quiet)
	st.Log = log
	if cmd.Run == nil {
		// Container command: with leftover non-flag arguments the first one
		// is an unknown subcommand — a usage error, not silent success.
		if len(fs.Args()) > 0 {
			fmt.Fprintln(stderr, "unknown command:", strings.Join(fs.Args(), " "))
			cmd.printHelp(stderr, path)
			return ExitUsage
		}
		cmd.printHelp(stdout, path)
		return ExitOK
	}

	// Context-bound run with graceful shutdown reporting.
	runErr := cmd.Run(ctx, st, fs.Args(), fs)
	if runErr != nil {
		if isCancellation(runErr) || ctx.Err() != nil {
			fmt.Fprintln(stderr, "interrupted; shutdown complete (partial results are stored in the session database)")
			return ExitRuntime
		}
		fmt.Fprintln(stderr, "error:", runErr.Error())
		return exitCodeFor(runErr)
	}
	return ExitOK
}

// exitCodeFor maps classified errors to exit codes.
func exitCodeFor(err error) int {
	var fe findingsExit
	if errorsAs(err, &fe) {
		return ExitFindingsFound
	}
	var se silentScopeDenial
	if errorsAs(err, &se) {
		return ExitScope
	}
	if ee, ok := err.(exitError); ok {
		return int(ee) // explicit exit code (e.g. doctor failures → ExitConfig)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "out of scope"):
		return ExitScope
	case strings.Contains(msg, "config") || strings.Contains(msg, "profile") || strings.Contains(msg, "auth file"):
		return ExitConfig
	default:
		return ExitRuntime
	}
}

// errorsAs is a tiny errors.As for the two error types used here.
func errorsAs(err error, target any) bool {
	switch t := target.(type) {
	case *findingsExit:
		if e, ok := err.(findingsExit); ok {
			*t = e
			return true
		}
	case *silentScopeDenial:
		if e, ok := err.(silentScopeDenial); ok {
			*t = e
			return true
		}
	}
	return false
}

func isCancellation(err error) bool {
	return err == context.Canceled || strings.Contains(err.Error(), "cancelled")
}

// resolve walks the command tree following args, returning the deepest
// matching command and the remaining arguments (all tokens except the
// matched subcommand path, in original order). Global flags may appear
// before or after subcommands, like `git`/`docker`.
func resolve(root *Command, args []string) (*Command, []string, []string) {
	cur := root
	path := []string{root.Name}
	remaining := []string{}
	// Global flags that take a value — their value token is not a subcommand.
	valueFlags := map[string]bool{"--config": true, "--auth": true, "--log-level": true}
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			remaining = append(remaining, a)
			continue
		}
		if strings.HasPrefix(a, "-") {
			remaining = append(remaining, a)
			if valueFlags[strings.SplitN(a, "=", 2)[0]] {
				skipNext = true // next token is this flag's value
			}
			continue
		}
		matched := false
		for _, sub := range cur.Sub {
			if sub.Name == a {
				cur = sub
				path = append(path, sub.Name)
				matched = true
				break
			}
		}
		if !matched {
			remaining = append(remaining, a)
		}
	}
	return cur, remaining, path
}

func (c *Command) printHelp(w io.Writer, path []string) {
	name := strings.Join(path, " ")
	fmt.Fprintf(w, "%s — %s\n\n", name, c.Short)
	if c.Long != "" {
		fmt.Fprintln(w, strings.TrimSpace(c.Long)+"\n")
	}
	fmt.Fprintf(w, "Usage:\n  %s %s\n", name, c.Usage)
	if len(c.Sub) > 0 {
		fmt.Fprintln(w, "\nSubcommands:")
		for _, sub := range c.Sub {
			fmt.Fprintf(w, "  %-22s %s\n", sub.Name, sub.Short)
		}
	}
	if c.Examples != nil || len(c.Examples) > 0 {
		fmt.Fprintln(w, "\nExamples:")
		for _, ex := range c.Examples {
			fmt.Fprintf(w, "  %s\n", ex)
		}
	}
}

// boolFlag reads a registered boolean flag's current value.
func boolFlag(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	b, _ := strconv.ParseBool(f.Value.String())
	return b
}

// flagValues returns the accumulated values of a repeatable flag (empty when
// the flag is not registered or not set).
func flagValues(fs *flag.FlagSet, name string) []string {
	f := fs.Lookup(name)
	if f == nil {
		return nil
	}
	if rf, ok := f.Value.(*repeatFlag); ok {
		return rf.values
	}
	return nil
}

// strFlag reads a registered string flag's current value.
func strFlag(fs *flag.FlagSet, name string) string {
	f := fs.Lookup(name)
	if f == nil {
		return ""
	}
	return f.Value.String()
}

// bootstrap builds the shared runtime from configuration files.
type runtime struct {
	cfg *config.Config
	sc  *scope.Checker
	se  *safety.Engine
	cl  *httpclient.Client
	am  *auth.Manager
	db  *storage.DB
	ev  *evidence.Engine
	ve  *verification.Engine
}

func bootstrap(ctx context.Context, cfgPath, authPath string, log *logger.Logger) (*runtime, error) {
	return bootstrapOverlay(ctx, cfgPath, authPath, log, nil)
}

// bootstrapOverlay builds the runtime with CLI flag overlays applied to the
// loaded configuration. The merged configuration is re-validated BEFORE any
// runtime object is constructed, so flag-driven scope or profile changes
// pass the same deny-by-default validation as file configuration.
func bootstrapOverlay(ctx context.Context, cfgPath, authPath string, log *logger.Logger, overlay func(*config.Config) error) (*runtime, error) {
	cfg, err := config.Load(cfgPath, authPath)
	if err != nil {
		return nil, err
	}
	if overlay != nil {
		if err := overlay(cfg); err != nil {
			return nil, err
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("validate merged configuration: %w", err)
		}
	}
	if err := config.EnsureDir(cfg.Session.OutputDir); err != nil {
		return nil, fmt.Errorf("create output dir %s: %w", cfg.Session.OutputDir, err)
	}
	dbPath := cfg.Session.OutputDir + "/owntrace.db"
	db, err := storage.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.RecoverInterrupted(); err != nil {
		log.Warnf("recover interrupted sessions: %v", err)
	}
	sc, err := scope.New(cfg.Scope)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("scope: %w", err)
	}
	se, err := safety.New(safety.Config{
		RatePerSecond:     cfg.Limits.RatePerSecond,
		PerHostRatePerSec: cfg.Limits.RatePerSecond,
		Concurrency:       cfg.Limits.Concurrency,
		WriteAllowed:      cfg.Safety.AllowWriteMethods,
		BlockDestructive:  cfg.Safety.BlockDestructive,
		BlockedPatterns:   cfg.Scope.BlockedPathPatterns,
		MaxRetries:        cfg.Limits.Retries,
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("safety: %w", err)
	}
	se.Scope = sc
	cl := httpclient.New(se, log, time.Duration(cfg.Limits.RequestTimeoutSecs)*time.Second,
		cfg.Limits.MaxResponseBytes, cfg.Limits.MaxRedirects, cfg.Limits.Retries)
	if strings.TrimSpace(cfg.Network.ProxyURL) != "" {
		if perr := cl.SetProxy(cfg.Network.ProxyURL); perr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("proxy: %w", perr)
		}
		log.Infof("requests routed through proxy %s (dial guard still enforced)", cfg.Network.ProxyURL)
	}
	am, err := auth.New(cfg, log)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	ev := evidence.NewEngine(db)
	ve := &verification.Engine{
		Client: cl, Auth: am, Scope: sc, Evid: ev, Store: db,
		Cfg: cfg.Verification, Log: log,
	}
	return &runtime{cfg: cfg, sc: sc, se: se, cl: cl, am: am, db: db, ev: ev, ve: ve}, nil
}

func (rt *runtime) close() { _ = rt.db.Close() }

// sortedStrings returns a sorted copy.
func sortedStrings(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}
