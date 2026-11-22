// Package report generates JSON, Markdown, HTML and CSV reports from stored
// session data. Reports never fabricate severity or CVSS scores, always
// distinguish confirmed / suspected / inconclusive / rejected / error
// findings, and embed evidence references suitable for human review.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/storage"
	"github.com/Lutfifakee-Project/owntrace/internal/version"
)

// Data is everything a report needs.
type Data struct {
	Title    string                        `json:"title"`
	Session  storage.Session               `json:"session"`
	Config   *config.Config                `json:"config"` // redacted copy
	Findings []*finding.Finding            `json:"findings"`
	Objects  []*storage.ObjectRow          `json:"objects"`
	Evidence map[string][]*evidence.Record `json:"evidence"` // finding ID -> evidence
	// EvidenceIntegrityFailures lists evidence records that FAILED hash
	// verification at export time (v0.7.0: reports never silently embed
	// tampered evidence).
	EvidenceIntegrityFailures []string       `json:"evidence_integrity_failures,omitempty"`
	Counts                    map[string]int `json:"counts"`
	Generated                 time.Time      `json:"generated"`
	Version                   string         `json:"tool_version"`
}

// Collector gathers report data from the store.
type Collector struct {
	DB *storage.DB
}

// Collect loads all data for a session.
func (c *Collector) Collect(sessionID, title string, cfg *config.Config) (*Data, error) {
	sessions, err := c.DB.ListSessions()
	if err != nil {
		return nil, err
	}
	var sess *storage.Session
	for i := range sessions {
		if sessions[i].ID == sessionID {
			sess = &sessions[i]
			break
		}
	}
	if sess == nil {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	findings, err := c.DB.ListFindings(sessionID, "")
	if err != nil {
		return nil, err
	}
	objects, err := c.DB.ListObjects(sessionID)
	if err != nil {
		return nil, err
	}
	counts, err := c.DB.FindingCounts(sessionID)
	if err != nil {
		return nil, err
	}
	ev := map[string][]*evidence.Record{}
	var integrityFailures []string
	for _, f := range findings {
		recs, err := c.DB.GetEvidence(f.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if verr := r.Verify(); verr != nil {
				integrityFailures = append(integrityFailures, fmt.Sprintf("%s (finding %s): %v", r.ID, f.ID, verr))
			}
		}
		if len(recs) > 0 {
			ev[f.ID] = recs
		}
	}
	if title == "" {
		title = "OWNTRACE Authorization Test Report"
	}
	return &Data{
		Title:                     title,
		Session:                   *sess,
		Config:                    cfg.RedactedCopy(),
		Findings:                  findings,
		Objects:                   objects,
		Evidence:                  ev,
		EvidenceIntegrityFailures: integrityFailures,
		Counts:                    counts,
		Generated:                 time.Now().UTC(),
		Version:                   version.Version,
	}, nil
}

// JSON renders the machine-readable report.
func (d *Data) JSON() ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(jsonWriter(&buf))
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// CSV renders the tabular findings (one row per finding).
func (d *Data) CSV() ([]byte, error) {
	var b strings.Builder
	b.WriteString("finding_id,state,category,title,method,url,resource,identifier,owner_profile,owner_state,requester,confidence,reason\n")
	order := []string{"CONFIRMED", "SUSPECTED", "INCONCLUSIVE", "REJECTED", "ERROR"}
	byState := map[string][]*finding.Finding{}
	for _, f := range d.Findings {
		byState[string(f.State)] = append(byState[string(f.State)], f)
	}
	for _, state := range order {
		for _, f := range byState[state] {
			row := []string{
				f.ID, string(f.State), string(f.Category), f.Title, f.Method, f.URL,
				f.Resource, f.RedactedIdentifier(), f.OwnerProfile, f.OwnerState, f.Requester,
				fmt.Sprintf("%.2f", f.Confidence), f.Reason,
			}
			for i, v := range row {
				row[i] = csvEscape(v)
			}
			b.WriteString(strings.Join(row, ",") + "\n")
		}
	}
	return []byte(b.String()), nil
}

func csvEscape(v string) string {
	if strings.ContainsAny(v, ",\"\n") {
		return "\"" + strings.ReplaceAll(v, "\"", "\"\"") + "\""
	}
	return v
}

func stateOrder(f []*finding.Finding) []*finding.Finding {
	rank := map[string]int{"CONFIRMED": 0, "SUSPECTED": 1, "INCONCLUSIVE": 2, "REJECTED": 3, "ERROR": 4}
	out := append([]*finding.Finding(nil), f...)
	sort.SliceStable(out, func(i, j int) bool { return rank[string(out[i].State)] < rank[string(out[j].State)] })
	return out
}

// Markdown renders the human-readable report.
func (d *Data) Markdown() []byte {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# %s\n\n", d.Title)
	w("Generated: %s · Tool: OWNTRACE v%s · Session: `%s` (%s, %s)\n\n",
		d.Generated.Format(time.RFC3339), d.Version, d.Session.ID, d.Session.Name, d.Session.Status)

	// ---- executive summary ----
	w("## 1. Executive summary\n\n")
	total := len(d.Findings)
	w("This report presents the results of an automated object-level authorization test ")
	w("(IDOR/BOLA assessment) executed with OWNTRACE v%s. %d finding(s) were recorded; ", d.Version, total)
	w("every verdict is backed by captured request/response evidence and explicit verification controls.\n\n")
	w("| Verdict | Count | Meaning |\n|---|---|---|\n")
	meaning := map[string]string{
		"CONFIRMED":    "Reproduced unauthorized access with ownership evidence",
		"SUSPECTED":    "Likely issue; a confirmation condition was not fully met",
		"INCONCLUSIVE": "Testing could not establish a reliable baseline",
		"REJECTED":     "Control verified as working (no vulnerability)",
		"ERROR":        "Test could not complete (transport/config issue)",
	}
	for _, state := range []string{"CONFIRMED", "SUSPECTED", "INCONCLUSIVE", "REJECTED", "ERROR"} {
		w("| **%s** | %d | %s |\n", state, d.Counts[state], meaning[state])
	}
	w("\nNo severity ratings or CVSS scores are asserted: severity depends on application context and ")
	w("must be judged by a human reviewer before any disclosure.\n\n")

	// ---- scope ----
	w("## 2. Scope\n\n")
	if d.Config != nil && len(d.Config.Scope.Targets) > 0 {
		w("| Target host | Schemes | Include paths | Exclude paths | Allowed methods | Max requests |\n")
		w("|---|---|---|---|---|---|\n")
		for _, t := range d.Config.Scope.Targets {
			w("| `%s` | %s | %s | %s | %s | %d |\n", t.Host,
				joinOr(t.Schemes), joinOr(t.IncludePaths), joinOr(t.ExcludePaths), joinOr(t.AllowedMethods), t.MaxRequests)
		}
		w("\nGlobal method allowlist: %s. Subdomains auto-authorized: %v.\n\n",
			strings.Join(d.Config.Scope.GlobalAllowedMethods, ", "), d.Config.Scope.AllowSubdomains)
		w("All requests were enforced against this scope by the safety engine; out-of-scope redirects are blocked and recorded.\n\n")
	}

	// ---- methodology ----
	w("## 3. Testing methodology\n\n")
	w("OWNTRACE tests object-level authorization with **independent authentication profiles** and ")
	w("**evidence-based verification controls**. For every protected object the engine records:\n\n")
	w("1. **Owner baseline** — the owning profile requests the object; the response must contain the object's data.\n")
	w("2. **Negative control** — a nonexistent object of the same shape, requested as the attacker, establishes the app's denial behavior.\n")
	w("3. **Non-owner test** — a different authenticated profile requests the same object.\n")
	w("4. **Decision matrix** — denials (401/403), generic 404s matching the negative control, empty/generic 200s and cache artifacts are REJECTED; full object data returned to a non-owner is CONFIRMED only when identity separation, ownership evidence, repeatability and cache analysis all pass.\n")
	w("5. **Anonymous test** — the same object requested without credentials, where configured.\n\n")
	w("A finding is CONFIRMED **only** when all applicable conditions hold: in-scope target, known resource, ")
	w("evidence-backed ownership, working owner baseline, distinct unauthorized identity receiving the object's data, ")
	w("reproducibility, and no legitimate explanation (cache, decoy, listing). HTTP 200 alone, response similarity ")
	w("alone, or identifier presence alone never produce CONFIRMED. When a condition cannot be demonstrated, ")
	w("the verdict is SUSPECTED or INCONCLUSIVE with the missing condition explained.\n\n")

	// ---- objects / ownership ----
	if len(d.Objects) > 0 {
		w("## 4. Object ownership registry\n\n")
		w("| Resource | Identifier | Owner | Ownership state | Confidence |\n|---|---|---|---|---|\n")
		for _, o := range d.Objects {
			w("| %s | `%s` | %s | %s | %.2f |\n", o.Resource, redact.Text(o.Identifier), o.OwnerProfile, o.OwnerState, o.Confidence)
		}
		w("\nOwnership states: *confirmed* = created via a controlled workflow; *declared* = user-configured; ")
		w("*inferred* = derived from listing membership or tagged traffic; *unknown* = no evidence. ")
		w("Only confirmed/declared/inferred ownership can support a CONFIRMED verdict.\n\n")
	}

	// ---- findings ----
	w("## 5. Findings\n\n")
	ordered := stateOrder(d.Findings)
	if len(ordered) == 0 {
		w("No findings were recorded for this session.\n\n")
	}
	idx := 0
	for _, f := range ordered {
		idx++
		w("### 5.%d [%s] %s\n\n", idx, f.State, f.Title)
		w("- **Category:** %s\n", f.Category)
		w("- **Endpoint:** `%s %s`\n", f.Method, f.URL)
		w("- **Resource:** %s `%s`\n", f.Resource, f.RedactedIdentifier())
		w("- **Owner:** %s (ownership: %s) · **Requester:** %s\n", f.OwnerProfile, f.OwnerState, f.Requester)
		w("- **Confidence:** %.0f%%\n", f.Confidence*100)
		w("- **Verdict rationale:** %s\n\n", f.Reason)

		if len(f.Controls) > 0 {
			w("**Verification controls**\n\n| Control | Status | Profile | HTTP | Detail |\n|---|---|---|---|---|\n")
			for _, c := range f.Controls {
				w("| %s | %s | %s | %d | %s |\n", c.Name, c.Status, c.Profile, c.HTTPStatus, htmlEsc(c.Detail))
			}
			b.WriteString("\n")
		}
		if len(f.Reproduction) > 0 {
			w("**Reproduction** (credentials redacted — substitute your own test tokens)\n\n```bash\n")
			for _, s := range f.Reproduction {
				b.WriteString(s + "\n")
			}
			w("```\n\n")
		}
		if len(f.EvidenceIDs) > 0 {
			w("**Evidence:** %s (SHA-256 integrity-verified, see `owntrace results show --finding %s`)\n\n",
				strings.Join(unique(f.EvidenceIDs), ", "), f.ID)
		}
		if f.Remediation != "" {
			w("**Remediation:** %s\n\n", f.Remediation)
		}
	}

	// ---- authorization consistency analysis ----
	if notes := consistencyAnalysis(d.Findings); len(notes) > 0 {
		w("## 5b. Authorization consistency analysis\n\n")
		w("The same resource type shows **different enforcement outcomes across endpoints**.\n")
		w("This pattern (partial enforcement) is a common root cause of authorization gaps:\n\n")
		for _, n := range notes {
			w("- %s\n", n)
		}
		w("\n")
	}

	// ---- limitations ----
	w("## 6. Limitations and uncertainty\n\n")
	w("- Verdicts are based on controlled cross-account testing with the configured test identities; ")
	w("application behaviors not exercised here (state-dependent visibility, shared resources by design, ")
	w("time-limited grants) may legitimately explain SUSPECTED results.\n")
	w("- INCONCLUSIVE findings indicate a broken baseline (misconfigured profile, wrong identifier) rather than a vulnerability.\n")
	w("- REJECTED findings document working controls and are valuable for regression tracking.\n")
	w("- Only objects with evidence-backed ownership can reach CONFIRMED; objects with unknown ownership are never confirmed.\n")
	w("- Reports must be reviewed by a human before submission to any bug bounty platform or vendor.\n\n")

	if len(d.EvidenceIntegrityFailures) > 0 {
		w("## ⚠ Evidence integrity failures at export time\n\n")
		w("The following evidence records FAILED hash verification when this report was generated. ")
		w("Their contents must be treated as untrusted; do not rely on this report until the cause is investigated:\n\n")
		for _, e := range d.EvidenceIntegrityFailures {
			w("- %s\n", e)
		}
		w("\n")
	}

	w("---\n\n")
	w("*Report generated by OWNTRACE v%s. Credentials and personal data are redacted; ", d.Version)
	w("evidence records are integrity-hashed (SHA-256) and tamper-evident.*\n")
	return []byte(b.String())
}

// HTML renders a self-contained responsive HTML report.
func (d *Data) HTML() []byte {
	md := string(d.Markdown())
	// Escape and wrap; a full MD renderer is a dependency we avoid — we emit
	// the markdown in a <pre> for fidelity plus a summary header block.
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(d.Title) + `</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;color:#1a202c}
header{background:#111827;color:#f9fafb;padding:2rem 1.25rem}
header h1{margin:0 0 .5rem;font-size:clamp(1.4rem,4vw,2rem)}
header p{margin:.25rem 0;opacity:.85;font-size:.95rem}
main{max-width:60rem;margin:0 auto;padding:1.25rem}
.badges span{display:inline-block;margin:.15rem .3rem .15rem 0;padding:.3rem .7rem;border-radius:.4rem;font-size:.85rem;font-weight:600;color:#fff}
.b-confirmed{background:#b91c1c}.b-suspected{background:#d97706}.b-inconclusive{background:#6b7280}
.b-rejected{background:#15803d}.b-error{background:#7c3aed}
pre{background:#0f172a;color:#e2e8f0;padding:1rem;border-radius:.5rem;overflow-x:auto;font-size:.85rem;line-height:1.45;white-space:pre-wrap;word-break:break-word}
section{background:#fff;border:1px solid #e5e7eb;border-radius:.6rem;padding:1.25rem;margin:1rem 0}
@media(prefers-color-scheme:dark){body{background:#111827;color:#e5e7eb}section{background:#1f2937;border-color:#374151}}
</style>
</head>
<body>
<header><h1>` + html.EscapeString(d.Title) + `</h1>
<p>Session ` + html.EscapeString(d.Session.ID) + " · " + html.EscapeString(d.Session.Name) + " · OWNTRACE v" + html.EscapeString(d.Version) + `</p>
<p class="badges">` + badge("CONFIRMED", d.Counts["CONFIRMED"]) + badge("SUSPECTED", d.Counts["SUSPECTED"]) +
		badge("INCONCLUSIVE", d.Counts["INCONCLUSIVE"]) + badge("REJECTED", d.Counts["REJECTED"]) + badge("ERROR", d.Counts["ERROR"]) + `</p>
</header>
<main><section>
<h2>Full report</h2>
<pre>` + html.EscapeString(md) + `</pre>
</section></main>
</body></html>
`)
	return []byte(b.String())
}

func badge(state string, n int) string {
	if n == 0 {
		return ""
	}
	return `<span class="b-` + strings.ToLower(state) + `">` + state + ": " + fmt.Sprint(n) + "</span>"
}

func joinOr(ss []string) string {
	if len(ss) == 0 {
		return "—"
	}
	return strings.Join(ss, ", ")
}

func unique(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func htmlEsc(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// jsonWriter is a tiny strings.Builder adapter.
type sbWriter struct{ b *strings.Builder }

func (w sbWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
func jsonWriter(b *strings.Builder) sbWriter   { return sbWriter{b} }

// consistencyAnalysis flags resource types whose endpoints show mixed
// authorization outcomes (e.g. one endpoint enforcing ownership while
// another serving the same resource to any authenticated user).
func consistencyAnalysis(findings []*finding.Finding) []string {
	type outcome struct {
		confirmed, rejected bool
		urls                []string
	}
	byResource := map[string]*outcome{}
	order := []string{}
	for _, f := range findings {
		if f.Resource == "" {
			continue
		}
		o := byResource[f.Resource]
		if o == nil {
			o = &outcome{}
			byResource[f.Resource] = o
			order = append(order, f.Resource)
		}
		switch f.State {
		case finding.StateConfirmed:
			o.confirmed = true
		case finding.StateRejected:
			o.rejected = true
		}
		if len(o.urls) < 4 {
			o.urls = append(o.urls, f.URL)
		}
	}
	var notes []string
	for _, res := range order {
		o := byResource[res]
		if o.confirmed && o.rejected {
			notes = append(notes, fmt.Sprintf("resource %q is enforced on some endpoints but exposed on others: %s — review all endpoints of this resource together",
				res, strings.Join(o.urls, ", ")))
		}
	}
	return notes
}
