// Workflow orchestration (§25): operator-provided flow files are executed
// per profile — owner runs establish controlled creation (confirmed
// ownership, §21) and policy-declared flows are re-run as unauthorized
// principals for the business-flow battery (§24).
package scan

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/evidence"
	"github.com/Lutfifakee-Project/owntrace/internal/ownership"
	"github.com/Lutfifakee-Project/owntrace/internal/workflow"
)

// runWorkflows executes every declared flow with its owner profile. Flow
// state is captured as evidence; extracted object identifiers become
// CONFIRMED ownership records (controlled creation).
func (r *Runner) runWorkflows(ctx context.Context, sessionID string, reg *ownership.Registry, sum *Summary) error {
	files, err := workflow.LoadFiles(r.Cfg.Workflows.Files, os.ReadFile)
	if err != nil {
		return err
	}
	x := &workflow.Executor{Client: r.Client, Auth: r.Auth, Scope: r.Scope, Log: r.Log, Base: firstTargetBase(r.Cfg)}
	for _, f := range files {
		for i := range f.Flows {
			fl := &f.Flows[i]
			if strings.TrimSpace(fl.OwnerProfile) == "" {
				sum.Notes = append(sum.Notes, fmt.Sprintf("workflow %s: no owner_profile — skipped for ownership establishment", fl.Name))
				continue
			}
			ownerRun := x.Run(ctx, fl, fl.OwnerProfile)
			if _, cerr := r.Evid.Capture("", sessionID, evidence.KindWorkflow, "owner flow "+fl.Name, ownerRun.RedactedCopy()); cerr != nil {
				r.Log.Warnf("workflow evidence capture failed: %v", cerr)
			}
			if !ownerRun.OK {
				return fmt.Errorf("flow %s as owner %s failed: %s", fl.Name, fl.OwnerProfile, ownerRun.Err)
			}
			if id := identifierFromState(ownerRun.State); id != "" && strings.TrimSpace(fl.Resource) != "" {
				reg.Upsert(&ownership.Record{
					Resource:     fl.Resource,
					Identifier:   id,
					OwnerProfile: fl.OwnerProfile,
					State:        ownership.StateConfirmed,
					Confidence:   0.95,
					EndpointPath: ownerRun.ObjectSurfaceURL(),
					SessionID:    sessionID,
					Provenance: []endpoints.SourceRef{{
						Kind: endpoints.SourceWorkflow, Location: "workflow " + fl.Name,
					}},
					Notes: "created by operator workflow " + fl.Name + " (controlled creation)",
				})
				r.Log.Infof("workflow %s: confirmed ownership of %s %s for %s", fl.Name, fl.Resource, id, fl.OwnerProfile)
			}
		}
	}
	return nil
}

// runBusinessFlows re-executes policy-declared flows as an unauthorized
// principal and routes the observation through the business-flow battery.
func (r *Runner) runBusinessFlows(ctx context.Context, sessionID string, sum *Summary) {
	files, err := workflow.LoadFiles(r.Cfg.Workflows.Files, os.ReadFile)
	if err != nil {
		sum.Notes = append(sum.Notes, "business flows: "+err.Error())
		return
	}
	x := &workflow.Executor{Client: r.Client, Auth: r.Auth, Scope: r.Scope, Log: r.Log, Base: firstTargetBase(r.Cfg)}
	names := r.Auth.Names()
	for _, f := range files {
		for i := range f.Flows {
			fl := &f.Flows[i]
			if strings.TrimSpace(fl.Policy) == "" || strings.TrimSpace(fl.OwnerProfile) == "" {
				continue // battery needs a declared policy and an owner
			}
			// Owner re-run (state proof); the ownership pass already ran it,
			// but a fresh run keeps the state evidence within this battery.
			ownerRun := x.Run(ctx, fl, fl.OwnerProfile)
			if !ownerRun.OK {
				sum.Notes = append(sum.Notes, fmt.Sprintf("business flow %s: owner run failed (%s) — preconditions not established, battery skipped", fl.Name, ownerRun.Err))
				continue
			}
			// Pick an attacker: any profile other than the owner.
			attacker := ""
			for _, n := range names {
				if n != fl.OwnerProfile {
					attacker = n
					break
				}
			}
			if attacker == "" {
				continue
			}
			if findingsBudgetExhausted(sum, r.Cfg.Verification) {
				return
			}
			// Repeatability: one attempt per configured repeat.
			var attackerRuns []*workflow.RunResult
			repeats := r.Cfg.Verification.Repeats
			if repeats < 1 {
				repeats = 1
			}
			blocked := false
			for rep := 0; rep < repeats && ctx.Err() == nil; rep++ {
				run := x.Run(ctx, fl, attacker)
				attackerRuns = append(attackerRuns, run)
				if _, cerr := r.Evid.Capture("", sessionID, evidence.KindWorkflow,
					fmt.Sprintf("unauthorized flow %s as %s (attempt %d)", fl.Name, attacker, rep+1), run.RedactedCopy()); cerr != nil {
					r.Log.Warnf("workflow evidence capture failed: %v", cerr)
				}
				if !run.OK && run.Denied {
					// The flow was refused by scope/safety before completing:
					// nothing to evaluate for this attacker.
					blocked = true
					break
				}
			}
			if blocked {
				sum.Notes = append(sum.Notes, fmt.Sprintf("business flow %s: unauthorized execution refused by scope — flow not testable as %s", fl.Name, attacker))
				continue
			}
			r.Verif.VerifyBusinessFlow(ctx, fl, ownerRun, attackerRuns)
		}
	}
}

// firstTargetBase renders the first scope target's base URL (scheme://host)
// for {{base}} substitution in workflow files.
func firstTargetBase(cfg *config.Config) string {
	if len(cfg.Scope.Targets) == 0 {
		return ""
	}
	t := cfg.Scope.Targets[0]
	scheme := "https"
	if len(t.Schemes) > 0 {
		scheme = t.Schemes[0]
	}
	return scheme + "://" + t.Host
}

// identifierFromState picks the flow's object identifier (last id-ish key).
func identifierFromState(state map[string]string) string {
	last := ""
	for k, v := range state {
		if v == "" {
			continue
		}
		if k == "id" || strings.HasSuffix(k, "_id") {
			last = v
		}
	}
	return last
}
