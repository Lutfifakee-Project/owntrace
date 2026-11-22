package report_test

import (
	"strings"
	"testing"
)

// v0.7.0: reports validate evidence at export time and WARN instead of
// silently embedding tampered records.
func TestReportWarnsOnTamperedEvidenceAtExport(t *testing.T) {
	data, _, _ := buildReportData(t)
	// Corrupt one evidence payload in the report data (simulating a tampered
	// store row that was loaded into the report).
	for fid, recs := range data.Evidence {
		for _, r := range recs {
			r.Data = []byte(`{"status": 599, "tampered": true}`)
			data.EvidenceIntegrityFailures = append(data.EvidenceIntegrityFailures,
				r.ID+" (finding "+fid+"): hash mismatch")
		}
	}
	md := string(data.Markdown())
	if !strings.Contains(md, "Evidence integrity failures at export time") {
		t.Fatal("tampered-evidence warning missing from report")
	}
	if !strings.Contains(md, "untrusted") {
		t.Fatal("untrusted-content guidance missing")
	}
	js := string(mustJSON(data))
	if !strings.Contains(js, "evidence_integrity_failures") {
		t.Fatal("JSON report lacks integrity-failure field")
	}
}

// The normal path embeds evidence without warnings.
func TestReportCleanEvidenceHasNoWarnings(t *testing.T) {
	data, _, _ := buildReportData(t)
	if len(data.EvidenceIntegrityFailures) != 0 {
		t.Fatalf("unexpected failures: %v", data.EvidenceIntegrityFailures)
	}
	md := string(data.Markdown())
	if strings.Contains(md, "Evidence integrity failures") {
		t.Fatal("warning present on clean evidence")
	}
}
