// Restricted-property exposure analysis for the BOPLA (property-level)
// verification battery (Master Prompt §24, §29). The operator declares the
// properties that must never be readable by unauthorized principals; the
// engine matches JSON key paths in the owner baseline and the unauthorized
// response to prove (or refute) unauthorized exposure.
package verification

import (
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/util"
)

// exposedRestrictedProps returns the declared restricted properties present
// in BOTH the owner baseline (the property is real on this object) and the
// unauthorized response (an unauthorized principal can read it). A property
// missing from the owner baseline does not exist on the object and cannot be
// "exposed" — treating it as exposed would fabricate a finding.
func (e *Engine) exposedRestrictedProps(ownerBody, attBody string) []string {
	if len(e.Cfg.RestrictedProperties) == 0 {
		return nil
	}
	ownerKeys := jsonKeyPaths(ownerBody)
	if len(ownerKeys) == 0 {
		return nil
	}
	attKeys := jsonKeyPaths(attBody)
	var out []string
	for _, prop := range e.Cfg.RestrictedProperties {
		prop = strings.TrimSpace(prop)
		if prop == "" {
			continue
		}
		if keyPathPresent(ownerKeys, prop) && keyPathPresent(attKeys, prop) {
			out = append(out, prop)
		}
	}
	return out
}

// jsonKeyPaths flattens a JSON document into dotted key paths
// ("data.user.salary"); array elements inherit their element's path.
func jsonKeyPaths(body string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	v, err := util.DecodeJSON([]byte(body))
	if err != nil {
		return nil
	}
	var paths []string
	walkKeys(v, "", &paths)
	return paths
}

func walkKeys(v any, prefix string, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			*out = append(*out, path)
			walkKeys(child, path, out)
		}
	case []any:
		for _, child := range t {
			walkKeys(child, prefix, out)
		}
	}
}

// keyPathPresent reports whether a declared property is present in the key
// paths, matching either the exact dotted path or any path ending in the
// property (a declared leaf name matches at any depth).
func keyPathPresent(paths []string, prop string) bool {
	for _, p := range paths {
		if p == prop || strings.HasSuffix(p, "."+prop) {
			return true
		}
	}
	return false
}
