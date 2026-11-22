package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDefaultMappingsCoverAllCategories proves every category has complete,
// well-formed default triage mappings (§34: CWE where appropriate, OWASP
// mapping, severity distinct from confidence and never fabricated CVSS).
func TestDefaultMappingsCoverAllCategories(t *testing.T) {
	for _, cat := range Categories() {
		sev := DefaultSeverity(cat)
		switch sev {
		case SevInfo, SevLow, SevMedium, SevHigh, SevCritical:
		default:
			t.Errorf("%s: default severity %q is not a known level", cat, sev)
		}
		if cwe := DefaultCWE(cat); !strings.HasPrefix(cwe, "CWE-") {
			t.Errorf("%s: default CWE %q is not CWE-prefixed", cat, cwe)
		}
		if o := DefaultOWASP(cat); !strings.HasPrefix(o, "API") || !strings.Contains(o, ":") {
			t.Errorf("%s: default OWASP %q is not an API-top10 mapping", cat, o)
		}
	}
}

// TestApplyDefaultsFillsAndRespectsOperator proves ApplyDefaults fills empty
// triage fields and never overwrites an operator severity decision.
func TestApplyDefaultsFillsAndRespectsOperator(t *testing.T) {
	f := &Finding{Category: CatHorizontal}
	f.ApplyDefaults()
	if f.Severity != DefaultSeverity(CatHorizontal) || f.SeveritySrc != "default" {
		t.Fatalf("severity default not applied: %q/%q", f.Severity, f.SeveritySrc)
	}
	if f.CWE == "" || f.OWASP == "" {
		t.Fatalf("CWE/OWASP defaults not applied: %q/%q", f.CWE, f.OWASP)
	}

	f2 := &Finding{Category: CatHorizontal}
	if err := f2.SetSeverity(SevLow); err != nil {
		t.Fatalf("SetSeverity: %v", err)
	}
	f2.ApplyDefaults()
	if f2.Severity != SevLow || f2.SeveritySrc != "operator" {
		t.Fatalf("operator severity overwritten: %q/%q", f2.Severity, f2.SeveritySrc)
	}
	if err := f2.SetSeverity("catastrophic"); err == nil {
		t.Fatal("SetSeverity accepted an unknown level")
	}
}

// TestAcceptRiskRules proves risk acceptance requires a justification and a
// verified state (CONFIRMED/SUSPECTED only) — §34 accepted-risk state.
func TestAcceptRiskRules(t *testing.T) {
	base := func(st State) *Finding {
		return &Finding{ID: "F-1", State: st, Category: CatHorizontal}
	}
	for _, st := range []State{StateConfirmed, StateSuspected} {
		if err := base(st).AcceptRisk("compensating controls", "boss"); err != nil {
			t.Errorf("state %s: AcceptRisk refused: %v", st, err)
		}
	}
	for _, st := range []State{StateInconclusive, StateRejected, StateError, StateTesting} {
		if err := base(st).AcceptRisk("compensating controls", "boss"); err == nil {
			t.Errorf("state %s: AcceptRisk should be refused", st)
		}
	}
	if err := base(StateConfirmed).AcceptRisk("   ", "boss"); err == nil {
		t.Error("AcceptRisk accepted an empty justification")
	}
}

// TestSuppressRules proves suppression requires a justification and a
// terminal state, and that IsSuppressed reflects the record (§34 suppression
// with justification; suppression never deletes).
func TestSuppressRules(t *testing.T) {
	base := func(st State) *Finding {
		return &Finding{ID: "F-2", State: st, Category: CatHorizontal}
	}
	for _, st := range []State{StateConfirmed, StateSuspected, StateInconclusive, StateRejected, StateError} {
		if err := base(st).Suppress("duplicate of F-9", "yukii"); err != nil {
			t.Errorf("state %s: Suppress refused: %v", st, err)
		}
	}
	for _, st := range []State{StateDiscovered, StateCandidate, StateTesting} {
		if err := base(st).Suppress("x", "y"); err == nil {
			t.Errorf("state %s: Suppress should be refused", st)
		}
	}
	if err := base(StateConfirmed).Suppress("", "yukii"); err == nil {
		t.Error("Suppress accepted an empty justification")
	}
	f := base(StateConfirmed)
	_ = f.Suppress("duplicate of F-9", "yukii")
	if !f.IsSuppressed() || f.Suppression.By != "yukii" {
		t.Fatal("suppression record not retained")
	}
}

// TestAdjacentCategoriesAreDistinctTypes proves BFLA, BOPLA and business-flow
// are separate finding types with their own IDs and remediations (§24: they
// are never folded into the object-level IDOR categories).
func TestAdjacentCategoriesAreDistinctTypes(t *testing.T) {
	ids := map[Category]string{}
	for _, cat := range []Category{CatVertical, CatBFLA, CatBOPLA, CatBusinessFlow, CatHorizontal} {
		ids[cat] = NewID("s", "e", string(cat), "42")
	}
	if ids[CatBFLA] == ids[CatVertical] {
		t.Fatal("BFLA and vertical share finding IDs — not separate types")
	}
	if ids[CatBOPLA] == ids[CatHorizontal] {
		t.Fatal("BOPLA and horizontal share finding IDs — not separate types")
	}
	for _, cat := range []Category{CatBFLA, CatBOPLA, CatBusinessFlow} {
		if DefaultRemediation(cat) == DefaultRemediation(CatHorizontal) {
			t.Errorf("%s: remediation identical to horizontal — category-specific guidance missing", cat)
		}
	}
}

// TestEnrichedFindingJSONRoundTrip proves the new fields survive JSON
// marshalling (reports and exports rely on it).
func TestEnrichedFindingJSONRoundTrip(t *testing.T) {
	f := &Finding{ID: "F-3", Category: CatBOPLA, State: StateConfirmed, Identifier: "d-1"}
	f.ApplyDefaults()
	f.AddTriageNote("yukii", "contains PII — raise with app team")
	_ = f.SetSeverity(SevHigh)
	_ = f.AcceptRisk("flagged for fix in Q3", "boss")
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var g Finding
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.Severity != SevHigh || g.SeveritySrc != "operator" || g.CWE != DefaultCWE(CatBOPLA) {
		t.Fatalf("triage fields lost: %+v", g)
	}
	if len(g.TriageNotes) != 1 || g.TriageNotes[0].Author != "yukii" {
		t.Fatalf("triage notes lost: %+v", g.TriageNotes)
	}
	if g.AcceptedRisk == nil || g.AcceptedRisk.By != "boss" {
		t.Fatalf("accepted risk lost: %+v", g.AcceptedRisk)
	}
}
