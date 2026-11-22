package report_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/report"
)

func TestConsistencyAnalysisFlagsMixedEnforcement(t *testing.T) {
	mk := func(state finding.State, url string) *finding.Finding {
		return &finding.Finding{State: state, URL: url, Resource: "order", Method: "GET",
			CreatedAt: time.Now(), UpdatedAt: time.Now()}
	}
	data := &report.Data{
		Findings: []*finding.Finding{
			mk(finding.StateConfirmed, "http://x/api/v1/orders/o-1001"),
			mk(finding.StateRejected, "http://x/api/v1/secure-orders/o-2001"),
		},
	}
	// The analysis is exercised through the Markdown renderer (report body).
	md := string(data.Markdown())
	if !strings.Contains(md, "Authorization consistency analysis") {
		t.Fatal("consistency section missing for mixed-enforcement resources")
	}
	if !strings.Contains(md, `"order"`) {
		t.Fatal("resource not named in consistency notes")
	}
}

func TestConsistencyAnalysisSilentWhenUniform(t *testing.T) {
	mk := func(state finding.State, url string) *finding.Finding {
		return &finding.Finding{State: state, URL: url, Resource: "invoice", Method: "GET",
			CreatedAt: time.Now(), UpdatedAt: time.Now()}
	}
	data := &report.Data{
		Findings: []*finding.Finding{
			mk(finding.StateRejected, "http://x/api/v1/invoices/inv-2001"),
			mk(finding.StateRejected, "http://x/api/v2/invoices/inv-2002"),
		},
	}
	md := string(data.Markdown())
	if strings.Contains(md, "Authorization consistency analysis") {
		t.Fatal("consistency section must be absent when enforcement is uniform")
	}
}
