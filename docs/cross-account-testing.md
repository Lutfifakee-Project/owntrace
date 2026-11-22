# Cross-Account Testing Guide

This is the core of OWNTRACE: how a candidate becomes (or fails to become) a
CONFIRMED finding.

## The parties

- **Owner** — the profile that legitimately owns (or may access) the object.
- **Attacker** — a different, identity-verified profile.
- **Anonymous** — no credentials at all (implicit profile `anon`).

## The verification battery

For each test item (object × endpoint) the engine runs, in order:

### 1. Identity separation
Probes both profiles' identity endpoints. Unverified separation caps the
verdict at SUSPECTED (or aborts testing entirely when
`require_identity_separation: true` — the default via
`auth.require_distinct_identities`).

### 2. Owner baseline
The owner requests the object. Requirements:
- transport success, no denial (401/403/404 fail the baseline),
- the response must contain the object's identifier (**resource identity**).

A failing baseline ⇒ `INCONCLUSIVE`: the configuration is wrong (bad
identifier, expired token), and no verdict about the application can be made.

### 3. Negative control
The attacker requests a **nonexistent** object of the same shape (identifiers
are mutated deterministically: numerics become out-of-range values, UUIDs a
fixed nil-UUID, opaque IDs gain a `-ot-nonexistent-zz` suffix). This records
how the app behaves when the object simply does not exist. It feeds two
checks: the generic-404 rejection and the decoy gate.

### 4. Non-owner access
The attacker requests the real object. The decision matrix:

| Observation | Verdict |
|---|---|
| 401 / 403 | `REJECTED` — authorization enforced |
| 404 identical to the negative control | `REJECTED` — existence hidden, access denied |
| 404 differing from the negative control | `SUSPECTED` — possible existence leak |
| Redirect to a login surface | `REJECTED` |
| Empty 200 | `REJECTED` |
| 200 + identifier + similarity ≥ 0.60 + owner-data field overlap ≥ 0.5 | `CONFIRMED` candidate |
| 200 + identifier but little object data (e.g. echo decoys) | `REJECTED` — generic content |
| 200 + identifier, partial/transformed data | `SUSPECTED` |
| 200 similar to baseline without identifier | `SUSPECTED` |
| 200 unrelated content | `REJECTED` |
| Endpoint answers 2xx (similar body) for the *nonexistent* object too | `REJECTED` — decoy, does not resolve objects |

The **owner-data field overlap** compares the scalar values of the owner's
JSON response against the attacker's: a real object read carries the object's
data; a marketing page that happens to echo the id does not.

### 5. Cache analysis (cache-bust)
When a candidate confirms, the same request is re-sent with a unique cache
busting query parameter. If the busted request no longer shows access, the
original response likely came from a shared cache holding the owner's copy →
verdict drops to `SUSPECTED` with the cache control marked FAIL.

### 6. Public-content probe
The same request **without credentials**. If anonymous access yields the same
object data, the content is not identity-protected at all: the horizontal
finding becomes `REJECTED` ("public content — covered by the anonymous
finding") and the separate **anonymous** finding captures the exposure. This
keeps genuinely public data out of the horizontal category and filters decoys
that serve identical content to everyone.

### 7. Repeatability
The attacker's request repeats `verification.repeats` times (default 2).
Every repeat must show access, or the verdict degrades to `INCONCLUSIVE`
(flaky or conditional behavior).

### 8. Gates before CONFIRMED
- ownership state ≥ configured floor (`min_owner_state_for_confirmed`,
  default `declared`; unknown ownership can never confirm),
- identity separation verified (when required),
- repeatability passed,
- cache analysis passed.

## Test categories

| Category | Trigger |
|---|---|
| `horizontal_object_access` | Default for owned objects |
| `cross_tenant_access` | Declared objects carrying a `tenant` value |
| `nested_resource_authorization` | URLs where a child-resource segment (`notes`, `payments`, `items`, ...) follows an identifier, or URLs with ≥ 2 identifier segments |
| `broken_function_level_authorization` | Privileged endpoints under `admin_path_patterns`; admin-role profile is the baseline, a non-admin profile the attacker (function-level, §24) |
| `anonymous_access` | Same item requested without credentials (when `anonymous_test: true`) |

## Vertical testing details

`vertical_test` needs role context: configure `role: admin` on the admin
profile. The engine tests adminish endpoints discovered in scope. Without an
admin + non-admin pair, vertical tests are skipped (no baseline → no
verdict), and nothing is claimed.

## Multi-tenant testing

Declare tenant-scoped objects with their tenant:

```yaml
objects:
  declared:
    - { profile: userA, resource: file, url: ".../tenants/t-acme/files/f-9001", identifiers: ["f-9001"], tenant: "t-acme" }
    - { profile: userB, resource: file, url: ".../tenants/t-globex/files/f-9002", identifiers: ["f-9002"], tenant: "t-globex" }
```

When the attacker profile's tenant differs from the owner's, the finding is
categorized `cross_tenant_access`.

## Re-running and regression tracking

`owntrace verify --finding F-XXXX` re-runs the battery for one finding;
`--state SUSPECTED` re-verifies every suspected finding. Transitions are
appended, never overwritten — the history shows how a verdict evolved.
`REJECTED` findings are kept deliberately: they document working controls and
make authorization regressions visible between runs.
