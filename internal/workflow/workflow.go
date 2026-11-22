// Package workflow implements the stateful application-workflow engine
// (Master Prompt §25): operator-provided ordered request sequences with
// state variables, dynamic value extraction, preconditions (expectations),
// fail-closed step execution, a negative control for flow authorization
// testing, and safe cleanup. Workflows feed the ownership registry
// (controlled creation → confirmed ownership) and the sensitive
// business-flow verification battery (§24).
//
// Fail-closed semantics: a step whose expectation is not met aborts the
// flow (cleanup still runs), and a flow without a declared policy or
// negative control can never support a business-flow CONFIRMED verdict.
package workflow

import (
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is one operator-provided workflow document.
type File struct {
	Version     int    `yaml:"version" json:"version"`
	Description string `yaml:"description" json:"description"`
	Flows       []Flow `yaml:"flows" json:"flows"`
}

// Flow is one ordered multi-request sequence.
type Flow struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	// OwnerProfile receives any identifiers this flow creates (controlled
	// creation → confirmed ownership, §21). Required when the flow extracts
	// identifiers; optional for pure probe flows.
	OwnerProfile string `yaml:"owner_profile" json:"owner_profile"`
	Resource     string `yaml:"resource" json:"resource"`
	// Policy declares the expected access rule (§29: business-flow verdicts
	// require a known expected policy). Flows used for business-flow testing
	// MUST declare one; omitting it only weakens the flow's own verdict.
	Policy string `yaml:"policy" json:"policy"`
	Steps  []Step `yaml:"steps" json:"steps"`
	// NegativeControl is an INVALID variant of a state-changing step
	// (nonexistent object, malformed id). It MUST be denied by the
	// application; a successful negative control marks the flow as a decoy
	// and blocks business-flow confirmation (fail-closed).
	NegativeControl *Step `yaml:"negative_control" json:"negative_control"`
	// Cleanup runs best-effort after the flow (success, failure or denial).
	Cleanup []Step `yaml:"cleanup" json:"cleanup"`
}

// Step is one request with optional extraction and expectation.
type Step struct {
	Name    string             `yaml:"name" json:"name"`
	Method  string             `yaml:"method" json:"method"`
	URL     string             `yaml:"url" json:"url"`
	Headers map[string]string  `yaml:"headers" json:"headers"`
	Body    string             `yaml:"body" json:"body"`
	Extract map[string]Extract `yaml:"extract" json:"extract"`
	Expect  *Expect            `yaml:"expect" json:"expect"`
}

// Extract pulls a value from a step response into the flow state.
type Extract struct {
	From string `yaml:"from" json:"from"` // json | header
	Path string `yaml:"path" json:"path"` // JSON dot path or header name
}

// Expect is a precondition: the response must satisfy it or the flow aborts.
type Expect struct {
	Status   int    `yaml:"status" json:"status"`     // exact status (0 = any 2xx)
	Contains string `yaml:"contains" json:"contains"` // literal substring of the body
}

// ParseFile parses and validates one workflow document.
func ParseFile(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// LoadFiles parses every listed workflow file. An unreadable or invalid file
// is an error (fail-closed): no partial workflow set is returned.
func LoadFiles(paths []string, read func(string) ([]byte, error)) ([]*File, error) {
	var out []*File
	for _, p := range paths {
		b, err := read(p)
		if err != nil {
			return nil, fmt.Errorf("workflow %s: %w", p, err)
		}
		f, err := ParseFile(b)
		if err != nil {
			return nil, fmt.Errorf("workflow %s: %w", p, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// Validate checks structural sanity with actionable errors.
func (f *File) Validate() error {
	if len(f.Flows) == 0 {
		return fmt.Errorf("workflow file declares no flows")
	}
	for i, fl := range f.Flows {
		if strings.TrimSpace(fl.Name) == "" {
			return fmt.Errorf("flows[%d]: name is required", i)
		}
		if len(fl.Steps) == 0 {
			return fmt.Errorf("flow %q: at least one step is required", fl.Name)
		}
		if len(fl.Steps) > 32 {
			return fmt.Errorf("flow %q: more than 32 steps (unbounded sequences are refused)", fl.Name)
		}
		for j, st := range fl.Steps {
			if err := validateStep(&st, fmt.Sprintf("flow %q steps[%d]", fl.Name, j)); err != nil {
				return err
			}
		}
		if fl.NegativeControl != nil {
			if err := validateStep(fl.NegativeControl, fmt.Sprintf("flow %q negative_control", fl.Name)); err != nil {
				return err
			}
		}
		for j, st := range fl.Cleanup {
			if err := validateStep(&st, fmt.Sprintf("flow %q cleanup[%d]", fl.Name, j)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateStep(st *Step, where string) error {
	if st.URL == "" {
		return fmt.Errorf("%s: url is required", where)
	}
	u, err := url.Parse(st.URL)
	if err != nil {
		return fmt.Errorf("%s: invalid url: %w", where, err)
	}
	switch u.Scheme {
	case "http", "https":
	case "":
		// Template with a placeholder base ({{base}}/path): the scheme cannot
		// be validated yet. Enforcement happens at execution time — every
		// substituted URL must pass the deny-by-default scope checker, which
		// only accepts hosts configured for the run.
		if !strings.HasPrefix(strings.TrimSpace(st.URL), "{{") {
			return fmt.Errorf("%s: url must be absolute (scheme missing)", where)
		}
	default:
		return fmt.Errorf("%s: url scheme must be http or https", where)
	}
	if st.Method != "" {
		switch strings.ToUpper(st.Method) {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		default:
			return fmt.Errorf("%s: unsupported method %q", where, st.Method)
		}
	}
	for name, ex := range st.Extract {
		switch ex.From {
		case "json", "header":
		default:
			return fmt.Errorf("%s: extract %q: from must be json or header", where, name)
		}
		if ex.Path == "" {
			return fmt.Errorf("%s: extract %q: path is required", where, name)
		}
	}
	return nil
}
