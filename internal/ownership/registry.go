// Package ownership maintains the registry that maps discovered objects to the
// authentication profile that owns them. Ownership quality drives whether a
// finding may ever reach CONFIRMED: only evidence-backed ownership allows a
// confirmed verdict, per the verification policy.
package ownership

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
)

// State expresses how strongly ownership is established.
type State string

const (
	// StateConfirmed: OWNTRACE created or observed the object being created by
	// the profile in a controlled workflow.
	StateConfirmed State = "confirmed"
	// StateDeclared: the user explicitly declared the mapping in configuration.
	StateDeclared State = "declared"
	// StateInferred: OWNTRACE inferred ownership from evidence (e.g. the object
	// appears in the profile's own collection listing, or in traffic tagged as
	// that profile). Inferred ownership must never be presented as confirmed.
	StateInferred State = "inferred"
	// StateUnknown: no reliable ownership evidence.
	StateUnknown State = "unknown"
)

// AllowedForConfirmed lists ownership states that may support a CONFIRMED
// vulnerability verdict. Inferred and unknown ownership must NEVER support
// confirmation (Master Prompt §4.2): inferred ownership is derived from
// heuristics (listing membership, tagged traffic) and can be wrong; only a
// controlled creation (confirmed) or an explicit operator declaration
// (declared) establishes trusted owner provenance. This function takes no
// configuration input — the invariant is not weakenable.
func AllowedForConfirmed(s State) bool {
	return s == StateConfirmed || s == StateDeclared
}

// Record is one entry in the ownership registry.
type Record struct {
	ID           string                `json:"id"`
	Resource     string                `json:"resource"`
	Identifier   string                `json:"identifier"` // raw identifier (kept locally; redacted on export)
	EndpointID   string                `json:"endpoint_id"`
	EndpointPath string                `json:"endpoint_path,omitempty"`
	OwnerProfile string                `json:"owner_profile"`
	State        State                 `json:"owner_state"`
	Confidence   float64               `json:"confidence"`
	Tenant       string                `json:"tenant,omitempty"` // tenant scoping, if known
	Provenance   []endpoints.SourceRef `json:"provenance"`
	SessionID    string                `json:"session_id,omitempty"`
	CreatedAt    time.Time             `json:"created_at"`
	Notes        string                `json:"notes,omitempty"`
}

// Key identifies an object: resource + identifier + endpoint identity. The
// endpoint PATH participates so the same identifier surfacing at two URLs
// (e.g. an object endpoint and a redirect surface) stays separately testable.
func (r *Record) Key() string {
	return r.Resource + "|" + r.Identifier + "|" + r.EndpointID + "|" + r.EndpointPath
}

// RedactedIdentifier renders the identifier safe for reports: identifiers that
// look like credentials, e-mails or long opaque tokens are masked.
func (r *Record) RedactedIdentifier() string {
	return redactIdentifier(r.Identifier)
}

func redactIdentifier(id string) string {
	if len(id) > 64 || looksSecretish(id) {
		h := sha256.Sum256([]byte(id))
		return "obj_" + hex.EncodeToString(h[:])[:12]
	}
	return id
}

func looksSecretish(s string) bool {
	if len(s) < 24 {
		return false
	}
	for _, r := range s {
		if r == '@' { // e-mail
			return true
		}
	}
	return true // long opaque tokens are treated as sensitive
}

// Registry is a concurrency-safe ownership registry.
type Registry struct {
	mu      sync.RWMutex
	records map[string]*Record
}

func NewRegistry() *Registry {
	return &Registry{records: map[string]*Record{}}
}

// Upsert inserts or merges an ownership record. On conflict the higher-quality
// state wins (confirmed > declared > inferred > unknown) and confidence is
// kept at the maximum. Returns the stored record.
func (g *Registry) Upsert(r *Record) *Record {
	if r.ID == "" {
		r.ID = computeID(r.Key())
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if existing, ok := g.records[r.Key()]; ok {
		if stateRank(r.State) > stateRank(existing.State) {
			existing.State = r.State
			existing.OwnerProfile = r.OwnerProfile
		}
		if r.Confidence > existing.Confidence {
			existing.Confidence = r.Confidence
		}
		if existing.Tenant == "" {
			existing.Tenant = r.Tenant
		}
		if existing.EndpointPath == "" {
			existing.EndpointPath = r.EndpointPath
		}
		existing.Provenance = mergeSources(existing.Provenance, r.Provenance)
		existing.SessionID = r.SessionID
		return existing
	}
	g.records[r.Key()] = r
	return r
}

func stateRank(s State) int {
	switch s {
	case StateConfirmed:
		return 4
	case StateDeclared:
		return 3
	case StateInferred:
		return 2
	default:
		return 1
	}
}

func computeID(key string) string {
	h := sha256.Sum256([]byte(key))
	return "obj_" + hex.EncodeToString(h[:])[:12]
}

func mergeSources(a, b []endpoints.SourceRef) []endpoints.SourceRef {
	for _, s := range b {
		found := false
		for _, d := range a {
			if d == s {
				found = true
				break
			}
		}
		if !found {
			a = append(a, s)
		}
	}
	return a
}

// Lookup finds a record by resource + identifier + endpoint ID.
func (g *Registry) Lookup(resource, identifier, endpointID string) (*Record, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	// Deterministic best match: records may exist for the same object at
	// different endpoint paths; report the highest-quality one (state rank,
	// then confidence) so lookups never depend on map iteration order.
	var best *Record
	for _, r := range g.records {
		if r.Resource != resource || r.Identifier != identifier || r.EndpointID != endpointID {
			continue
		}
		if best == nil || stateRank(r.State) > stateRank(best.State) ||
			(stateRank(r.State) == stateRank(best.State) && r.Confidence > best.Confidence) {
			best = r
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

// ByProfile returns records attributed to a profile.
func (g *Registry) ByProfile(profile string) []*Record {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []*Record
	for _, r := range g.records {
		if r.OwnerProfile == profile {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// List returns all records sorted by key.
func (g *Registry) List() []*Record {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*Record, 0, len(g.records))
	for _, r := range g.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// ObjectsOfOtherProfiles returns objects owned by profiles other than the
// given one — the test targets for cross-account access.
func (g *Registry) ObjectsOfOtherProfiles(profile string) []*Record {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []*Record
	for _, r := range g.records {
		if r.OwnerProfile != profile && r.OwnerProfile != "" {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// String renders a record for logs (identifier redacted).
func (r *Record) String() string {
	return fmt.Sprintf("%s %s (owner=%s, state=%s)", r.Resource, r.RedactedIdentifier(), r.OwnerProfile, r.State)
}
