package scan_test

// Accounting regression tests (owner acceptance defects, 2026-11-22).
//
// Issue 1: the scan summary used to count finding EVENTS — a role-matrix
// battery testing one privileged endpoint against several attackers produced
// ONE upserted finding row but was counted once per attacker, so the CLI
// summary disagreed with report.json and results list. The invariant under
// test: CLI summary == report.json == results list == persisted cardinality.
//
// Issue 2: a check refused by the destructive-path guard BEFORE its first
// request used to be counted as executed (coverage "N/N, 0 safety-skipped").
// It must be accounted as safety-skipped, never as executed.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/owntrace/internal/cli"
	"github.com/Lutfifakee-Project/owntrace/internal/storage"
)

// summaryStates parses the human scan summary ("Findings by state:") section.
func summaryStates(t *testing.T, stdout string) map[string]int {
	t.Helper()
	out := map[string]int{}
	re := regexp.MustCompile(`(?m)^\s+(CONFIRMED|SUSPECTED|INCONCLUSIVE|REJECTED|ERROR)\s+(\d+)\s*$`)
	for _, m := range re.FindAllStringSubmatch(stdout, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("bad count %q: %v", m[2], err)
		}
		out[m[1]] = n
	}
	if len(out) == 0 {
		t.Fatalf("no findings section in scan summary:\n%s", stdout)
	}
	return out
}

// summaryCoverage parses the "Authorization coverage: E/P ... S safety-skipped" line.
func summaryCoverage(t *testing.T, stdout string) (executed, planned, skipped int) {
	t.Helper()
	re := regexp.MustCompile(`Authorization coverage: (\d+)/(\d+) planned check\(s\) executed, (\d+) safety-skipped`)
	m := re.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("no coverage line in scan summary:\n%s", stdout)
	}
	for i, v := range []string{m[1], m[2], m[3]} {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("bad coverage number %q: %v", v, err)
		}
		switch i {
		case 0:
			executed = n
		case 1:
			planned = n
		case 2:
			skipped = n
		}
	}
	return
}

func resultsListCounts(t *testing.T, e *e2eEnv) map[string]int {
	t.Helper()
	var out bytes.Buffer
	code := cli.Main([]string{"results", "list", "--json",
		"--config", filepath.Join(e.dir, "owntrace.yaml"),
		"--auth", filepath.Join(e.dir, "auth.yaml"), "--log-level", "error"}, &out, &out)
	if code != 0 {
		t.Fatalf("results list failed (exit %d): %s", code, out.String())
	}
	var parsed struct {
		Findings []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("parse results list JSON: %v\n%s", err, out.String())
	}
	c := map[string]int{}
	for _, f := range parsed.Findings {
		c[f.State]++
	}
	return c
}

func reportJSONCounts(t *testing.T, e *e2eEnv) map[string]int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.dir, "data", "reports", "report.json"))
	if err != nil {
		t.Fatalf("read report.json: %v", err)
	}
	var rep struct {
		Findings []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("parse report.json: %v", err)
	}
	c := map[string]int{}
	for _, f := range rep.Findings {
		c[f.State]++
	}
	return c
}

func dbCounts(t *testing.T, e *e2eEnv, sessionID string) map[string]int {
	t.Helper()
	db, err := storage.Open(e.dbPath())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	c, err := db.CountFindingsByState(sessionID)
	if err != nil {
		t.Fatalf("count findings by state: %v", err)
	}
	return c
}

// summarySessionID parses "Session: S-..." from the scan summary.
func summarySessionID(t *testing.T, stdout string) string {
	t.Helper()
	re := regexp.MustCompile(`Session:\s+(S-\S+)`)
	m := re.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("no session id in scan summary:\n%s", stdout)
	}
	return m[1]
}

func assertEqualCounts(t *testing.T, want map[string]int, got map[string]int, what string) {
	t.Helper()
	totalWant, totalGot := 0, 0
	for k, v := range want {
		totalWant += v
		if got[k] != v {
			t.Fatalf("%s: state %s: persisted %d, %s reports %d", what, k, v, what, got[k])
		}
	}
	for k, v := range got {
		totalGot += v
		if want[k] != v {
			t.Fatalf("%s: unexpected state %s=%d (persisted %d)", what, k, v, want[k])
		}
	}
	if totalWant != totalGot {
		t.Fatalf("%s: total mismatch: persisted %d vs %s %d", what, totalWant, what, totalGot)
	}
}

// TestScanSummaryMatchesPersistedCounts is the Issue-1 regression: with a
// vertical role-matrix battery (one privileged endpoint tested against two
// non-admin attackers) the old code reported one extra CONFIRMED finding.
// Every persisted surface must agree, and total counts must equal the actual
// persisted finding cardinality.
func TestScanSummaryMatchesPersistedCounts(t *testing.T) {
	env := setupE2E(t, false)
	sid := summarySessionID(t, env.stdout)
	states := summaryStates(t, env.stdout)

	results := resultsListCounts(t, env)
	assertEqualCounts(t, states, results, "results list")

	report := reportJSONCounts(t, env)
	assertEqualCounts(t, states, report, "report.json")

	db := dbCounts(t, env, sid)
	assertEqualCounts(t, states, db, "database (CountFindingsByState)")

	// Cardinality: the number of findings rows is exactly the total of the
	// state counts (no phantom events).
	total := 0
	for _, v := range db {
		total += v
	}
	rows, err := storage.Open(env.dbPath())
	if err != nil {
		t.Fatal(err)
	}
	list, err := rows.ListFindings(sid, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != total {
		t.Fatalf("state-count total %d != persisted finding cardinality %d", total, len(list))
	}
	// The role-matrix duplicate must still exist as events, but never as
	// extra rows: at least one CONFIRMED finding from the vertical battery.
	if db["CONFIRMED"] == 0 {
		t.Fatalf("expected CONFIRMED findings from vertical battery, got %v", db)
	}
}

// TestSafetySkippedDestructiveNestedGETAccounting is the Issue-2 regression:
// GET /api/v1/invoices/inv-2001/payments matches the destructive-path pattern
// (?i)payment and is refused BEFORE its first request (deny-by-default; the
// guard intentionally stays method-agnostic). The object battery AND the
// anonymous follow-up battery for that item are both safety-skipped, and the
// coverage line must say so instead of claiming every check executed.
func TestSafetySkippedDestructiveNestedGETAccounting(t *testing.T) {
	env := setupE2E(t, false)
	executed, planned, skipped := summaryCoverage(t, env.stdout)

	if skipped < 2 {
		t.Fatalf("expected >=2 safety-skipped checks (object + anonymous battery on the blocked nested GET), got %d", skipped)
	}
	if executed+skipped != planned {
		t.Fatalf("coverage accounting broken: executed %d + safety-skipped %d != planned %d", executed, skipped, planned)
	}
	if executed >= planned {
		t.Fatalf("blocked check still counted as executed: %d/%d", executed, planned)
	}

	// The persisted finding must carry the explicit safety refusal reason.
	db, err := storage.Open(env.dbPath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sid := summarySessionID(t, env.stdout)
	list, err := db.ListFindings(sid, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range list {
		if strings.Contains(f.Reason, "safety guard refused every request") {
			found = true
			if !strings.Contains(f.Reason, "destructive") {
				t.Fatalf("safety refusal reason should name the destructive-path policy: %s", f.Reason)
			}
			if f.State != "INCONCLUSIVE" {
				t.Fatalf("blocked check state = %s, want INCONCLUSIVE", f.State)
			}
		}
	}
	if !found {
		t.Fatalf("no finding carries the explicit safety-guard refusal reason")
	}
}
