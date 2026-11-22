// Business-flow verification battery (Master Prompt §24, §29): a workflow
// execution observed under an UNAUTHORIZED principal is evaluated against
// the §29 flow prerequisites — workflow state, authorized principal,
// expected policy, validated side effects — plus a negative control,
// repeatability and persisted evidence. Flow findings carry the separate
// sensitive_business_flow_bypass category and never masquerade as IDOR.
package verification

import (
	"context"
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/finding"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/workflow"
)

// VerifyBusinessFlow evaluates one flow's unauthorized execution(s).
// ownerRun is the owner-profile execution that proves the flow state;
// attackerRuns are the unauthorized executions (one per repeat). The flow
// MUST have declared a policy and a negative control for a CONFIRMED path —
// anything less downgrades (fail-closed).
func (e *Engine) VerifyBusinessFlow(ctx context.Context, fl *workflow.Flow, ownerRun *workflow.RunResult, attackerRuns []*workflow.RunResult) *finding.Finding {
	e.stats.attempts.Add(1)
	attacker := ""
	if len(attackerRuns) > 0 {
		attacker = attackerRuns[0].Profile
	}
	item := TestItem{
		URL:        lastRunStepURL(attackerRuns),
		Method:     lastRunStepMethod(attackerRuns),
		Resource:   flowResource(fl),
		Identifier: identifierFromRuns(attackerRuns),
		Owner:      fl.OwnerProfile,
		OwnerState: ownership.StateConfirmed,
		Category:   finding.CatBusinessFlow,
		EndpointID: "workflow-" + fl.Name,
		Note:       fl.Policy,
	}
	title := fmt.Sprintf("business-flow bypass: %q executed as unauthorized %s", fl.Name, attacker)
	f := e.newFinding(item, title)
	e.persist(f)

	cand := Candidate{
		Category:          finding.CatBusinessFlow,
		OwnerState:        ownership.StateConfirmed,
		EvidencePersisted: true,
	}

	// Identity separation (owner vs attacker) — §29 authorized principal.
	sep := e.Auth.VerifySeparation(ctx, e.Client, []string{fl.OwnerProfile, attacker})
	switch {
	case sep.Distinct && sep.Verified:
		cand.IdentityDistinct = true
		f.AddControl(finding.Control{Name: finding.ControlIdentitySeparation, Status: finding.StatusPass,
			Detail: "distinct identities verified via identity probes"})
	case !sep.Distinct:
		cand.IdentitySameIdentity = true
		cand.IdentityUnverified = true
		f.AddControl(finding.Control{Name: finding.ControlIdentitySeparation, Status: finding.StatusFail,
			Detail: sep.Detail, EvidenceID: e.captureVerification(f, sep)})
	default:
		cand.IdentityUnverified = true
		f.AddControl(finding.Control{Name: finding.ControlIdentitySeparation, Status: finding.StatusSkip,
			Detail: sep.Detail, EvidenceID: e.captureVerification(f, sep)})
	}

	// Evidence: both runs (owner establishes state, attacker proves bypass).
	if _, err := e.Evid.Capture(f.ID, e.Session, evidence.KindWorkflow, "owner flow execution "+fl.Name, ownerRun); err != nil {
		e.Log.Errorf("evidence capture failed (owner flow): %v", err)
		cand.EvidencePersisted = false
	}
	for i, run := range attackerRuns {
		if _, err := e.Evid.Capture(f.ID, e.Session, evidence.KindWorkflow,
			fmt.Sprintf("unauthorized flow execution %s (attempt %d)", fl.Name, i+1), run); err != nil {
			e.Log.Errorf("evidence capture failed (attacker flow): %v", err)
			cand.EvidencePersisted = false
		}
	}
	f.AddControl(finding.Control{Name: "flow_state", Status: passFail(ownerRun.OK),
		Profile: ownerRun.Profile, Detail: "owner flow completed: " + boolText(ownerRun.OK)})

	// §29 battery inputs.
	cand.FlowStateKnown = ownerRun.OK
	cand.FlowPolicyKnown = strings.TrimSpace(fl.Policy) != ""
	cand.NegativeControlDone = len(attackerRuns) > 0 && attackerRuns[0].NegControlDenied
	cand.AccessObserved = len(attackerRuns) > 0 && attackerRuns[0].OK

	// Repeatability: every attacker attempt must succeed (flaky bypass is
	// INCONCLUSIVE at the policy level via missing RepeatOK).
	repeatOK := len(attackerRuns) > 0
	for _, run := range attackerRuns {
		if !run.OK {
			repeatOK = false
		}
	}
	cand.RepeatOK = repeatOK
	status := finding.StatusPass
	if !repeatOK {
		status = finding.StatusFail
	}
	f.AddControl(finding.Control{Name: finding.ControlRepeatability, Status: status,
		Profile: attacker, Detail: fmt.Sprintf("unauthorized execution reproduced %d/%d time(s)", okCount(attackerRuns), len(attackerRuns))})

	f.Requester = attacker
	conf := 0.9
	verdict, reason := cand.Evaluate()
	if verdict != finding.StateConfirmed {
		conf = 0.55
	}
	f.Reason = reason
	e.finish(f, verdict, conf, reason, "")
	return f
}

// identifierFromRuns picks the flow's object identifier from the extracted
// state (the last id-ish key), for finding coordinates and reports.
func identifierFromRuns(runs []*workflow.RunResult) string {
	for i := len(runs) - 1; i >= 0; i-- {
		if id := identifierFromState(runs[i].State); id != "" {
			return id
		}
	}
	return ""
}

func identifierFromState(state map[string]string) string {
	if state == nil {
		return ""
	}
	last := ""
	for k, v := range state {
		if k == "id" || strings.HasSuffix(k, "_id") {
			if v != "" {
				last = v
			}
		}
	}
	return last
}

func lastRunStepURL(runs []*workflow.RunResult) string {
	if len(runs) == 0 {
		return ""
	}
	if st := runs[len(runs)-1].LastRealStep(); st != nil {
		return st.URL
	}
	return ""
}

func lastRunStepMethod(runs []*workflow.RunResult) string {
	if len(runs) == 0 {
		return "GET"
	}
	if st := runs[len(runs)-1].LastRealStep(); st != nil {
		return st.Method
	}
	return "GET"
}

func flowResource(fl *workflow.Flow) string {
	if strings.TrimSpace(fl.Resource) != "" {
		return fl.Resource
	}
	return "business-flow:" + fl.Name
}

func okCount(runs []*workflow.RunResult) int {
	n := 0
	for _, r := range runs {
		if r.OK {
			n++
		}
	}
	return n
}

func passFail(ok bool) string {
	if ok {
		return finding.StatusPass
	}
	return finding.StatusFail
}

func boolText(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// redactedState renders a flow state for reports without leaking raw values
// (values are redacted the same way as other report content).
func redactedState(state map[string]string) string {
	parts := make([]string, 0, len(state))
	for k, v := range state {
		parts = append(parts, k+"="+redact.Value(v))
	}
	return strings.Join(parts, ", ")
}
