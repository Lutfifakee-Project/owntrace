package report_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/report"
	"github.com/Lutfifakee-Project/owntrace/internal/storage"
)

func buildReportData(t *testing.T) (*report.Data, *storage.DB, string) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sid, _ := db.BeginSession("reporting", "{}")

	mk := func(id, state string, cat finding.Category, url, ident, owner string) *finding.Finding {
		now := time.Now().UTC()
		f := &finding.Finding{
			ID: id, SessionID: sid, Category: cat, State: finding.State(state),
			Title: "Test finding " + id, Method: "GET", URL: url, Resource: "order",
			Identifier: ident, OwnerProfile: owner, OwnerState: "declared", Requester: "userB",
			Confidence: 0.9, Reason: "evidence-based test reason", Remediation: "fix it",
			Controls:     []finding.Control{{Name: "owner_baseline", Status: "PASS", Profile: owner}},
			Reproduction: []string{"# as userA\ncurl -sS -H 'Authorization: Bearer ‹redacted:abcd1234›' " + url},
			CreatedAt:    now, UpdatedAt: now,
		}
		if err := db.SaveFinding(f); err != nil {
			t.Fatal(err)
		}
		rec, err := evidence.Build("EV-"+id, id, sid, evidence.KindHTTPExchange, "exchange",
			map[string]any{"status": 200, "body": "‹redacted:x›"})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SaveEvidence(rec); err != nil {
			t.Fatal(err)
		}
		return f
	}
	mk("F-CONF01", "CONFIRMED", finding.CatHorizontal, "http://api.test/api/orders/o-1001", "o-1001", "userA")
	mk("F-SUSP01", "SUSPECTED", finding.CatVertical, "http://api.test/api/admin/stats", "stats", "admin")
	mk("F-REJE01", "REJECTED", finding.CatHorizontal, "http://api.test/api/invoices/inv-2001", "inv-2001", "userA")

	cfg := &config.Config{}
	cfg.Report.Title = "Unit Report"
	col := &report.Collector{DB: db}
	data, err := col.Collect(sid, "Unit Report", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return data, db, sid
}

func TestMarkdownReportContent(t *testing.T) {
	data, _, _ := buildReportData(t)
	md := string(data.Markdown())
	for _, want := range []string{
		"Unit Report", "Executive summary", "CONFIRMED", "SUSPECTED", "REJECTED",
		"Testing methodology", "owner_baseline", "curl", "Limitations",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if strings.Contains(md, "hunter2") {
		t.Error("unexpected secret")
	}
}

func TestJSONReportStructure(t *testing.T) {
	data, _, _ := buildReportData(t)
	j, err := data.JSON()
	if err != nil {
		t.Fatal(err)
	}
	s := string(j)
	if !strings.Contains(s, `"CONFIRMED"`) || !strings.Contains(s, `"F-CONF01"`) {
		t.Error("json report missing findings")
	}
	if strings.Contains(s, `"token": "real"`) {
		t.Error("json report leaks secrets")
	}
}

func TestCSVReport(t *testing.T) {
	data, _, _ := buildReportData(t)
	csv := string(mustCSV(data))
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 4 { // header + 3 findings
		t.Fatalf("csv rows: %d\n%s", len(lines), csv)
	}
	if !strings.HasPrefix(lines[0], "finding_id,state,category") {
		t.Fatal("csv header wrong")
	}
}

func TestHTMLReportResponsive(t *testing.T) {
	data, _, _ := buildReportData(t)
	html := string(data.HTML())
	for _, want := range []string{
		`<meta name="viewport" content="width=device-width, initial-scale=1">`,
		"max-width", "CONFIRMED",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestEvidenceHashStable(t *testing.T) {
	data, _, _ := buildReportData(t)
	if len(data.Evidence) == 0 {
		t.Fatal("no evidence in report data")
	}
	for fid, recs := range data.Evidence {
		for _, r := range recs {
			if err := r.Verify(); err != nil {
				t.Errorf("evidence for %s fails integrity: %v", fid, err)
			}
		}
	}
}

func TestWriteReportFiles(t *testing.T) {
	data, _, _ := buildReportData(t)
	dir := t.TempDir()
	for name, content := range map[string][]byte{
		"r.md":   data.Markdown(),
		"r.json": mustJSON(data),
		"r.html": data.HTML(),
		"r.csv":  mustCSV(data),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 4 {
		t.Fatal("files not written")
	}
}
