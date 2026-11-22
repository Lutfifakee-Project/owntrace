package scan_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2EGraphQLNodeBypass proves the §26 adapter end-to-end: a GraphQL
// operation harvested from HAR traffic is matched to a declared object and
// the engine confirms the unauthorized node read through the object-level
// battery (transport recorded in the finding title).
func TestE2EGraphQLNodeBypass(t *testing.T) {
	env := setupE2E(t, false)
	base := env.srv.URL

	// HAR fixture: one GraphQL POST observed from alice's session.
	harPath := filepath.Join(env.dir, "traffic.har")
	har := fmt.Sprintf(`{"log":{"entries":[{"startedDateTime":"2026-11-21T08:00:00Z","time":5,
		"request":{"method":"POST","url":"%s/graphql",
			"headers":[{"name":"Authorization","value":"Bearer tok-alice-fixed-lab-token"},{"name":"Content-Type","value":"application/json"}],
			"postData":{"mimeType":"application/json","text":"{\"query\":\"query($id:String!){node(id:$id){id owner title}}\",\"variables\":{\"id\":\"doc-3001\"}}"}},
		"response":{"status":200,"content":{"mimeType":"application/json","text":"{\"data\":{\"node\":{\"id\":\"doc-3001\",\"owner\":\"alice\",\"title\":\"T\"}}}"}}}]}}`, base)
	if err := os.WriteFile(harPath, []byte(har), 0o600); err != nil {
		t.Fatal(err)
	}

	// Register the HAR file + enable POST for the GraphQL surface.
	cfgPath := filepath.Join(env.dir, "owntrace.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	extended := strings.Replace(string(raw), "sources: [\"url\"]", fmt.Sprintf(
		"sources: [\"url\", \"har\"]\n  har_files:\n    - %q", harPath), 1)
	extended = strings.ReplaceAll(extended,
		`allowed_methods: ["GET", "HEAD", "OPTIONS"]`,
		`allowed_methods: ["GET", "HEAD", "OPTIONS", "POST"]`)
	extended = strings.ReplaceAll(extended,
		`global_allowed_methods: ["GET", "HEAD", "OPTIONS"]`,
		`global_allowed_methods: ["GET", "HEAD", "OPTIONS", "POST"]`)
	extended = strings.ReplaceAll(extended,
		"allow_write_methods: false",
		"allow_write_methods: true")
	if err := os.WriteFile(cfgPath, []byte(extended), 0o600); err != nil {
		t.Fatal(err)
	}

	env.run(t, "scan")
	if env.exit != 5 {
		t.Fatalf("scan exit: want 5, got %d\n%s", env.exit, env.stdout)
	}
	by := env.findings(t)
	found := false
	for url, m := range by {
		if strings.Contains(url, "/graphql") && m["CONFIRMED"] && m["cat:horizontal_object_access"] {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no CONFIRMED GraphQL finding\n%s", env.stdout)
	}
}
