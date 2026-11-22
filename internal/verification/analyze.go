// Response comparison and denial-detection helpers used by the verification
// engine. These are heuristics feeding the decision matrix — never the sole
// basis for a CONFIRMED verdict.
package verification

import (
	"regexp"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/util"
)

// containsIdentifier reports whether the body references the identifier in a
// standalone way (word boundaries for numerics; case-insensitive for UUIDs).
func containsIdentifier(body, id string) bool {
	if body == "" || id == "" {
		return false
	}
	if isNumeric(id) {
		re := regexp.MustCompile(`(^|[^0-9])` + regexp.QuoteMeta(id) + `([^0-9]|$)`)
		return re.MatchString(body)
	}
	if looksUUID(id) {
		return strings.Contains(strings.ToLower(body), strings.ToLower(id))
	}
	return strings.Contains(body, id)
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func looksUUID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

// jaccardSimilarity compares two bodies by whitespace-token overlap. Redacted
// bodies share fingerprints for identical secrets, which keeps similarity
// meaningful after credential scrubbing. Inputs are capped for performance.
func jaccardSimilarity(a, b string) float64 {
	const cap = 8 << 10
	if len(a) > cap {
		a = a[:cap]
	}
	if len(b) > cap {
		b = b[:cap]
	}
	setA := tokenSet(a)
	setB := tokenSet(b)
	if len(setA) == 0 && len(setB) == 0 {
		return 1
	}
	if len(setA) == 0 || len(setB) == 0 {
		return 0
	}
	inter := 0
	for k := range setA {
		if _, ok := setB[k]; ok {
			inter++
		}
	}
	union := len(setA) + len(setB) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func tokenSet(s string) map[string]struct{} {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == ',' || r == ':' || r == '{' || r == '}' ||
			r == '[' || r == ']' || r == '"' || r == '(' || r == ')' || r == ';'
	})
	out := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		if len(f) > 1 { // skip punctuation residue
			out[f] = struct{}{}
		}
	}
	return out
}

// similarityThreshold is the minimum body similarity between the owner
// baseline and the cross-account response for "the same object data was
// returned" to hold. Deliberately high to avoid weak matches.
const similarityThreshold = 0.60

// dataFieldOverlap measures how many of the owner baseline's JSON scalar
// field values also appear in the non-owner response. A genuine object read
// returns the object's data; decoys or generic pages do not carry those
// field values. Returns (overlap, fieldCount).
func dataFieldOverlap(ownerBody, attBody string) (float64, int) {
	v := util.DecodeJSONLoose([]byte(ownerBody))
	if v == nil {
		return 0, 0
	}
	fields := 0
	present := 0
	util.WalkStrings(v, func(path string, s string) {
		if s == "" || len(s) > 128 {
			return
		}
		// Skip obviously structural/noise fields (timestamps, hrefs).
		fields++
		if strings.Contains(attBody, s) {
			present++
		}
	})
	if fields == 0 {
		return 0, 0
	}
	return float64(present) / float64(fields), fields
}

// overlapThreshold is the minimum share of owner data-field values that must
// appear in the non-owner response for a CONFIRMED verdict.
const overlapThreshold = 0.5

// denialKind classifies an access-denial response shape.
type denialKind int

const (
	denialNone          denialKind = iota
	denialAuth                     // 401/403 — explicit authorization rejection
	denialNotFound                 // 404/410-style hiding
	denialRedirectLogin            // redirected to an authentication surface
)

func classifyDenial(status int, body string) denialKind {
	switch status {
	case 401, 403:
		return denialAuth
	case 404, 410:
		return denialNotFound
	}
	lower := strings.ToLower(body)
	if status == 200 && (strings.Contains(lower, "\"error\"") && (strings.Contains(lower, "not_found") || strings.Contains(lower, "not found"))) {
		return denialNotFound
	}
	return denialNone
}

// mutatedIdentifier produces a controlled NONEXISTENT identifier of the same
// shape, used for the negative control: what does the app answer when the
// requested object simply does not exist for anyone?
func mutatedIdentifier(id string) string {
	if isNumeric(id) {
		// A clearly out-of-range numeric ID avoids colliding with a real
		// neighboring object (which would poison the negative control).
		return "999" + strings.Repeat("9", min(len(id), 8))
	}
	if looksUUID(id) {
		return "00000000-0000-4000-8000-ffffffffffff"[:36]
	}
	if len(id) >= 12 && isHex(id) {
		out := []byte(id)
		for i := range out {
			out[i] = 'f'
		}
		return string(out)
	}
	return id + "-ot-nonexistent-zz"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
