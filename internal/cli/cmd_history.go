// history implements the §14 history command: a chronological view of scan
// sessions with their finding tallies, so an operator can track assessments
// and regression over time without querying the database directly.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
)

func historyCmd() *Command {
	return &Command{
		Name:  "history",
		Short: "Show scan session history with finding tallies",
		Usage: "[--limit N] [--config path] [--json]",
		Long: "Lists all scan sessions, newest first, with per-session finding counts\n" +
			"by state (CONFIRMED/SUSPECTED/INCONCLUSIVE/REJECTED/ERROR). Useful for\n" +
			"comparing assessments of the same target over time.",
		Flags: func(fs *flag.FlagSet) {
			fs.Int("limit", 20, "maximum number of sessions to show")
			fs.Bool("json", false, "machine-readable output on stdout")
		},
		Run: func(ctx context.Context, s *State, args []string, fs *flag.FlagSet) error {
			rt, err := bootstrap(ctx, fs.Lookup("config").Value.String(), fs.Lookup("auth").Value.String(), s.Log)
			if err != nil {
				return err
			}
			defer rt.close()
			limit := 20
			if f := fs.Lookup("limit"); f != nil {
				limit, _ = strconv.Atoi(f.Value.String())
			}
			sessions, err := rt.db.ListSessions()
			if err != nil {
				return fmt.Errorf("list sessions: %w", err)
			}
			if limit > 0 && len(sessions) > limit {
				sessions = sessions[:limit]
			}
			type row struct {
				ID       string         `json:"id"`
				Name     string         `json:"name"`
				Status   string         `json:"status"`
				Started  string         `json:"started_at"`
				Findings map[string]int `json:"findings"`
			}
			rows := make([]row, 0, len(sessions))
			for _, sess := range sessions {
				counts, cerr := rt.db.FindingCounts(sess.ID)
				if cerr != nil {
					counts = map[string]int{}
				}
				rows = append(rows, row{ID: sess.ID, Name: sess.Name, Status: sess.Status, Started: sess.StartedAt, Findings: counts})
			}
			if boolFlag(fs, "json") {
				out, _ := json.MarshalIndent(rows, "", "  ")
				fmt.Fprintln(s.Out, string(out))
				return nil
			}
			if len(rows) == 0 {
				fmt.Fprintln(s.Out, "no scan sessions yet — run `owntrace scan` first")
				return nil
			}
			fmt.Fprintf(s.Out, "%-24s %-10s %-11s %-20s %s\n", "SESSION", "NAME", "STATUS", "STARTED (UTC)", "FINDINGS C/S/I/R/E")
			for _, r := range rows {
				tally := fmt.Sprintf("%d/%d/%d/%d/%d",
					r.Findings["CONFIRMED"], r.Findings["SUSPECTED"], r.Findings["INCONCLUSIVE"],
					r.Findings["REJECTED"], r.Findings["ERROR"])
				started := r.Started
				if len(started) > 19 {
					started = started[:19]
				}
				fmt.Fprintf(s.Out, "%-24s %-10s %-11s %-20s %s\n", r.ID, r.Name, r.Status, started, tally)
			}
			return nil
		},
	}
}
