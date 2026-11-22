// Workflow executor (§25): ordered requests with state substitution,
// expectation-gated steps (preconditions), dynamic extraction, explicit
// scope checks per step, and best-effort cleanup. A flow that fails a
// precondition never continues into unsafe territory.
package workflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/auth"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/redact"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
	"github.com/Lutfifakee-Project/owntrace/internal/util"
)

// Executor runs workflow flows as concrete profiles.
type Executor struct {
	Client *httpclient.Client
	Auth   *auth.Manager
	Scope  *scope.Checker
	Log    *logger.Logger
	// Base is exposed to flows as the {{base}} state variable (scheme://host
	// of the authorized target), so workflow files can be target-relative.
	Base string
}

// StepResult is the outcome of one executed step.
type StepResult struct {
	Step    string `json:"step"`
	Method  string `json:"method"`
	URL     string `json:"url"` // redacted
	Status  int    `json:"status,omitempty"`
	OK      bool   `json:"ok"`
	Refused bool   `json:"refused,omitempty"` // denied by scope/safety, never sent
	Detail  string `json:"detail,omitempty"`
}

// RunResult is the outcome of one flow execution.
type RunResult struct {
	Flow    string            `json:"flow"`
	Profile string            `json:"profile"`
	OK      bool              `json:"ok"`
	Denied  bool              `json:"denied,omitempty"` // refused by scope/safety before completing
	Err     string            `json:"error,omitempty"`
	State   map[string]string `json:"state,omitempty"`
	Steps   []StepResult      `json:"steps,omitempty"`
	// NegControlDenied reports the negative-control outcome (a flow without
	// a declared negative control never sets it — fail-closed for verdicts).
	NegControlDenied bool `json:"negative_control_denied,omitempty"`
}

// Run executes the flow as the given profile. Failures abort the flow and
// still run cleanup. The returned result is the flow's evidence record.
func (x *Executor) Run(ctx context.Context, fl *Flow, profile string) *RunResult {
	res := &RunResult{Flow: fl.Name, Profile: profile, State: map[string]string{"random": randToken()}}
	if x.Base != "" {
		res.State["base"] = strings.TrimSuffix(x.Base, "/")
	}
	for i := range fl.Steps {
		st := &fl.Steps[i]
		sr := x.runStep(ctx, st, profile, res.State)
		res.Steps = append(res.Steps, sr)
		if !sr.OK {
			if sr.Refused {
				res.Denied = true
			}
			res.Err = fmt.Sprintf("step %q failed: %s", st.Name, sr.Detail)
			x.cleanup(ctx, fl, profile, res.State, res)
			return res
		}
	}
	// Negative control runs AFTER the flow state is established: it probes
	// an INVALID variant of the sensitive operation (nonexistent object id)
	// and MUST be denied. A negative control that succeeds marks the flow
	// surface as a decoy and blocks any business-flow confirmation.
	if fl.NegativeControl != nil {
		denied, detail := x.runDenialProbe(ctx, fl, profile, res.State)
		res.NegControlDenied = denied
		res.Steps = append(res.Steps, StepResult{Step: "negative_control", Method: strings.ToUpper(orMethod(fl.NegativeControl.Method)),
			URL: redact.URL(x.substitute(fl.NegativeControl.URL, res.State)), OK: denied,
			Detail: "negative control outcome: " + detail})
		if !denied {
			res.Err = "negative control was NOT denied by the application (" + detail + ") — the flow surface is a decoy"
			x.cleanup(ctx, fl, profile, res.State, res)
			return res
		}
	}
	res.OK = true
	// Success-path cleanup: disposable objects created by the flow are
	// removed best-effort even when the flow completes (§25 safe cleanup).
	x.cleanup(ctx, fl, profile, res.State, res)
	x.Log.Infof("workflow %s as %s: %d step(s) completed", fl.Name, profile, len(fl.Steps))
	return res
}

// runDenialProbe executes the flow's negative control and reports whether
// the application denied it (denied=true is the expected, healthy outcome).
func (x *Executor) runDenialProbe(ctx context.Context, fl *Flow, profile string, state map[string]string) (bool, string) {
	st := fl.NegativeControl
	method := strings.ToUpper(orMethod(st.Method))
	if !x.Scope.Check(method, st.URL).Allowed {
		return false, "negative control URL out of scope"
	}
	xr := x.do(ctx, st, profile, state)
	if xr == nil || xr.Err != "" {
		return false, "transport error: " + transportText(xr)
	}
	if xr.Status >= 400 {
		return true, fmt.Sprintf("HTTP %d", xr.Status)
	}
	return false, fmt.Sprintf("HTTP %d with body", xr.Status)
}

// runStep executes one step with substitution, scope validation, auth
// headers, expectation checks and extraction.
func (x *Executor) runStep(ctx context.Context, st *Step, profile string, state map[string]string) StepResult {
	sr := StepResult{Step: st.Name, Method: strings.ToUpper(orMethod(st.Method))}
	urlStr := x.substitute(st.URL, state)
	sr.URL = redact.URL(urlStr)
	if !x.Scope.Check(sr.Method, urlStr).Allowed {
		sr.Refused = true
		sr.Detail = "refused by scope: " + urlStr
		return sr
	}
	xr := x.do(ctx, st, profile, state)
	if xr == nil || xr.Err != "" {
		sr.Detail = "transport error: " + transportText(xr)
		return sr
	}
	sr.Status = xr.Status
	if st.Expect != nil {
		if st.Expect.Status > 0 && xr.Status != st.Expect.Status {
			sr.Detail = fmt.Sprintf("expected HTTP %d, got %d", st.Expect.Status, xr.Status)
			return sr
		}
		if st.Expect.Status == 0 && (xr.Status < 200 || xr.Status >= 300) {
			sr.Detail = fmt.Sprintf("expected 2xx, got %d", xr.Status)
			return sr
		}
		if st.Expect.Contains != "" && !strings.Contains(xr.Body, st.Expect.Contains) {
			sr.Detail = fmt.Sprintf("body does not contain %q", st.Expect.Contains)
			return sr
		}
	}
	for name, ex := range st.Extract {
		v, ok := extractValue(xr, ex)
		if !ok {
			sr.Detail = fmt.Sprintf("extract %q: value not found (%s %s)", name, ex.From, ex.Path)
			return sr
		}
		state[name] = v
	}
	sr.OK = true
	sr.Detail = fmt.Sprintf("HTTP %d", xr.Status)
	return sr
}

// do sends one workflow request with the profile's credentials merged under
// the step's explicit headers (step headers win: CSRF correlation replaces
// the placeholder with the fresh token).
func (x *Executor) do(ctx context.Context, st *Step, profile string, state map[string]string) *httpclient.Exchange {
	method := strings.ToUpper(orMethod(st.Method))
	headers := map[string]string{}
	if h, err := x.Auth.Headers(profile); err == nil {
		for k, v := range h {
			headers[k] = v
		}
	} else {
		x.Log.Warnf("workflow %s: profile %s credentials: %v", st.Name, profile, err)
	}
	for k, v := range st.Headers {
		headers[k] = x.substitute(v, state)
	}
	opts := httpclient.Options{Headers: headers}
	if body := strings.TrimSpace(st.Body); body != "" {
		opts.Body = []byte(x.substitute(body, state))
	}
	x.Log.Debugf("workflow step %q: %s %s", st.Name, method, redact.URL(x.substitute(st.URL, state)))
	return x.Client.Do(ctx, method, x.substitute(st.URL, state), opts)
}

// cleanup runs the flow's cleanup steps best-effort (errors logged, never
// fatal) so failed flows do not leave disposable objects behind.
func (x *Executor) cleanup(ctx context.Context, fl *Flow, profile string, state map[string]string, res *RunResult) {
	for i := range fl.Cleanup {
		sr := x.runStep(ctx, &fl.Cleanup[i], profile, state)
		res.Steps = append(res.Steps, StepResult{Step: "cleanup:" + sr.Step, Method: sr.Method, URL: sr.URL, Status: sr.Status, OK: sr.OK, Detail: sr.Detail})
		if !sr.OK {
			x.Log.Warnf("workflow %s cleanup step %q failed: %s", fl.Name, sr.Step, sr.Detail)
		}
	}
}

// substitute replaces {{key}} placeholders with flow-state values.
func (x *Executor) substitute(tpl string, state map[string]string) string {
	if !strings.Contains(tpl, "{{") {
		return tpl
	}
	for k, v := range state {
		tpl = strings.ReplaceAll(tpl, "{{"+k+"}}", v)
	}
	return tpl
}

// extractValue pulls one value from the exchange per the extraction rule.
func extractValue(xr *httpclient.Exchange, ex Extract) (string, bool) {
	if xr == nil {
		return "", false
	}
	switch ex.From {
	case "header":
		for k, v := range xr.ResponseHeaders {
			if strings.EqualFold(k, ex.Path) {
				return v, true
			}
		}
		return "", false
	case "json":
		// Raw body first: workflow state must replay exact values (session
		// tokens, CSRF nonces), which the evidence-redacted Body masks.
		body := xr.RawBody
		if body == "" {
			body = xr.Body // synthetic exchanges (tests) may only set Body
		}
		v, err := util.DecodeJSON([]byte(body))
		if err != nil {
			return "", false
		}
		got, ok := util.GetPath(v, ex.Path)
		if !ok {
			return "", false
		}
		return util.Clamp(fmt.Sprintf("%v", got), 256), true
	default:
		return "", false
	}
}

func orMethod(m string) string {
	if strings.TrimSpace(m) == "" {
		return "GET"
	}
	return m
}

func transportText(xr *httpclient.Exchange) string {
	if xr == nil {
		return "no response"
	}
	if xr.Err != "" {
		return xr.Err
	}
	return fmt.Sprintf("HTTP %d", xr.Status)
}

func randToken() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LastRealStep returns the last non-synthetic step: negative-control and
// cleanup entries are excluded because they are not the flow's object
// surface (findings and ownership records must point at the real operation).
func (r *RunResult) LastRealStep() *StepResult {
	if r == nil {
		return nil
	}
	for i := len(r.Steps) - 1; i >= 0; i-- {
		st := &r.Steps[i]
		if st.Step == "negative_control" || strings.HasPrefix(st.Step, "cleanup:") {
			continue
		}
		return st
	}
	return nil
}

// ObjectSurfaceURL returns the URL that addresses the flow's created object
// for object-level testing: the last GET step (real steps only), falling
// back to the last real step when the flow has no read step.
func (r *RunResult) ObjectSurfaceURL() string {
	if r == nil {
		return ""
	}
	last := ""
	for i := range r.Steps {
		st := &r.Steps[i]
		if st.Step == "negative_control" || strings.HasPrefix(st.Step, "cleanup:") {
			continue
		}
		if strings.EqualFold(st.Method, "GET") {
			last = st.URL
		}
	}
	if last != "" {
		return last
	}
	if st := r.LastRealStep(); st != nil {
		return st.URL
	}
	return ""
}

// RedactedCopy returns an evidence-safe copy: extracted state values and
// error text are redacted, so tokens replayed by the flow never reach the
// evidence store, reports or exports.
func (r *RunResult) RedactedCopy() *RunResult {
	if r == nil {
		return nil
	}
	cp := *r
	cp.State = map[string]string{}
	for k, v := range r.State {
		cp.State[k] = redact.Value(v)
	}
	cp.Err = redact.Text(r.Err)
	steps := make([]StepResult, len(r.Steps))
	for i, st := range r.Steps {
		steps[i] = st
		steps[i].Detail = redact.Text(st.Detail)
	}
	cp.Steps = steps
	return &cp
}
