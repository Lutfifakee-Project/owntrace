package scan_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2EBusinessFlowBypass proves the §25 workflow engine end-to-end: the
// operator flow runs for its owner (controlled creation → confirmed
// ownership), the policy-declared flow is re-executed as an unauthorized
// principal, and the business-flow battery confirms the bypass as a
// separate sensitive_business_flow_bypass finding. The workflow-created
// document is also tested at object level (workflow read IDOR).
func TestE2EBusinessFlowBypass(t *testing.T) {
	env := setupE2E(t, false)

	// Workflow file against the lab (concrete URLs; {{base}} would resolve
	// to the scope target base in production).
	wfPath := filepath.Join(env.dir, "workflow.yaml")
	base := env.srv.URL
	wf := fmt.Sprintf(`
version: 1
flows:
  - name: doc-approval
    owner_profile: alice
    resource: workflow_doc
    policy: "approval restricted to approver/admin roles"
    steps:
      - name: csrf
        method: POST
        url: "%s/api/v1/workflows/csrf"
        extract: {csrf: {from: json, path: "token"}}
      - name: create-doc
        method: POST
        url: "%s/api/v1/workflows/docs"
        headers: {X-Flow-Token: "{{csrf}}"}
        body: '{"title":"owntrace-{{random}}"}'
        expect: {status: 201}
        extract: {doc_id: {from: json, path: "document.id"}}
      - name: read-doc
        method: GET
        url: "%s/api/v1/workflows/docs/{{doc_id}}"
        expect: {status: 200}
      - name: approve-doc
        method: POST
        url: "%s/api/v1/workflows/docs/{{doc_id}}/approve"
        headers: {X-Flow-Token: "{{csrf}}"}
        expect: {status: 200}
    negative_control:
      name: approve-nonexistent
      method: POST
      url: "%s/api/v1/workflows/docs/ot-neg-{{random}}/approve"
      headers: {X-Flow-Token: "{{csrf}}"}
`, base, base, base, base, base)
	if err := os.WriteFile(wfPath, []byte(wf), 0o600); err != nil {
		t.Fatal(err)
	}

	// Register the workflow in the config.
	cfgPath := filepath.Join(env.dir, "owntrace.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Workflow steps are state-changing (POST): the operator must authorize
	// POST explicitly — deny-by-default scope is never widened silently.
	extended := strings.Replace(string(raw), "report:", fmt.Sprintf(
		"workflows:\n  files:\n    - %q\n\nreport:", wfPath), 1)
	extended = strings.ReplaceAll(extended,
		`allowed_methods: ["GET", "HEAD", "OPTIONS"]`,
		`allowed_methods: ["GET", "HEAD", "OPTIONS", "POST"]`)
	extended = strings.ReplaceAll(extended,
		`global_allowed_methods: ["GET", "HEAD", "OPTIONS"]`,
		`global_allowed_methods: ["GET", "HEAD", "OPTIONS", "POST"]`)
	// Write-method gate (§42): state-changing workflow steps require the
	// operator's explicit opt-in.
	extended = strings.ReplaceAll(extended,
		"allow_write_methods: false",
		"allow_write_methods: true")
	if err := os.WriteFile(cfgPath, []byte(extended), 0o600); err != nil {
		t.Fatal(err)
	}

	env.run(t, "scan")
	if env.exit != 5 {
		t.Fatalf("scan exit: want 5 (confirmed findings incl. business flow), got %d\n%s", env.exit, env.stdout)
	}
	by := env.findings(t)

	// The business-flow bypass is its own finding category (§24).
	foundFlow := false
	for url, m := range by {
		if m["cat:sensitive_business_flow_bypass"] && m["CONFIRMED"] {
			foundFlow = true
			t.Logf("business-flow finding at %s", url)
			break
		}
	}
	if !foundFlow {
		t.Fatalf("no CONFIRMED sensitive_business_flow_bypass finding\n%s", env.stdout)
	}

	// The workflow-created document is confirmed-owned (controlled creation)
	// and its read surface is object-level tested.
	foundWfDoc := false
	for url, m := range by {
		if strings.Contains(url, "/api/v1/workflows/docs/") && m["CONFIRMED"] && m["cat:horizontal_object_access"] {
			foundWfDoc = true
			break
		}
	}
	if !foundWfDoc {
		t.Fatalf("workflow-created document not object-level confirmed\n%s", env.stdout)
	}
}
