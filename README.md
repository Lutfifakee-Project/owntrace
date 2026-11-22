# OWNTRACE

**Automated Object Ownership & Authorization Testing**

*Discover. Compare. Verify.*

OWNTRACE is a CLI-first, evidence-based security testing tool for **object-level
authorization failures** — the class of vulnerabilities commonly known as IDOR
(Insecure Direct Object Reference) and BOLA (Broken Object Level Authorization,
API1 in the OWASP API Security Top 10).

It tests whether a web application actually enforces *who may access which
object*, by comparing what **independent authentication profiles** can see —
and it refuses to call anything a vulnerability without reproducible evidence.

> ⚠️ **Authorized use only.** OWNTRACE is built for authorized security
> assessments, bug bounty programs with explicit scope, internal application
> testing, and controlled laboratories. Every request it sends is enforced
> against a deny-by-default scope that *you* configure. See
> [Scope & Safety](docs/scope-and-safety.md) and [SECURITY.md](SECURITY.md).

---

## What OWNTRACE does — and what it does not do

| OWNTRACE **does** | OWNTRACE **does not** |
|---|---|
| Discover endpoints from URLs, HAR captures, OpenAPI 3.x / Swagger 2.x documents and scope-bound crawling | Automatically attack every endpoint it finds without a configured scope |
| Maintain an **ownership registry** mapping objects to the profile that owns them (confirmed / declared / inferred / unknown) | Treat every field named `id` as an authorization-sensitive object |
| Run controlled **cross-account tests**: owner baseline → negative control → non-owner access → anonymous probe → cache analysis → repeatability | Claim a vulnerability from HTTP 200 alone, response similarity alone, or identifier presence alone |
| Verify that two profiles really are **different identities** before comparing them | Assume two different tokens mean two different users |
| Capture SHA-256 integrity-protected, credential-redacted evidence for every verdict | Store, log or export your credentials in plaintext |
| Produce human-reviewable JSON / Markdown / HTML / CSV reports | Fabricate CVSS scores, severity ratings or business impact |
| Refuse destructive operations (DELETE, payment paths, credential changes) unless explicitly and narrowly enabled | Bypass authentication, WAFs, rate limits or application safeguards |

**Core principle:** a finding must be supported by *authorization evidence*,
not merely response differences. When evidence is insufficient, OWNTRACE
reports `SUSPECTED` or `INCONCLUSIVE` — never a confident false positive.

---

## Installation

### Requirements
- Linux / macOS / Windows; ~50 MB disk; no database server (SQLite is embedded)

### From source (Go ≥ 1.22)

```bash
git clone https://github.com/Lutfifakee-Project/owntrace.git
cd owntrace
go build -trimpath -ldflags "-s -w -X github.com/Lutfifakee-Project/owntrace/internal/version.Commit=$(git rev-parse --short HEAD)" \
  -o owntrace ./cmd/owntrace
./owntrace version
```

### Verify the build
```bash
go vet ./... && go test ./...
```

See [docs/installation.md](docs/installation.md) for build details and
reproducibility notes.

---

## Quick start

### One-command scan of an authorized target

The normal scanning workflow is a single command. `owntrace scan` orchestrates
discovery, ownership mapping, authorization testing (IDOR/BOLA, BFLA, BOPLA),
repeatable verification, evidence collection with integrity hashes, and report
generation — no specialist commands are required for a routine engagement:

```bash
owntrace scan -u https://authorized.example --report=html
```

`-u` adds the authorized target to scope, `--report=html` writes the HTML
report, and exit code 5 signals CONFIRMED findings for CI pipelines. Run
`owntrace init` once for guided first-time setup of `owntrace.yaml` and
`auth.yaml`; advanced configuration and the specialist commands below remain
optional for deeper investigations.

### Guided lab walkthrough

This walks through testing the bundled vulnerable laboratory application.
All commands run from the repository root.

```bash
# 1. Start the deliberately vulnerable lab app (loopback only, test data only)
go run ./cmd/mockapp --addr 127.0.0.1:8099 &

# 2. Scaffold configuration
mkdir lab && cd lab
owntrace init                       # creates owntrace.yaml + auth.yaml (chmod 600)

# 3. Edit owntrace.yaml: point scope at the lab app
#    scope.targets[0].host = "127.0.0.1:8099"

# 4. Log in as two lab users and export tokens
export OT_USERA_TOKEN=$(curl -s http://127.0.0.1:8099/api/v1/login \
  -d '{"username":"alice","password":"pw-alice"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')
export OT_USERB_TOKEN=$(curl -s http://127.0.0.1:8099/api/v1/login \
  -d '{"username":"bob","password":"pw-bob"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')

# 5. Preview the plan — sends NO testing requests
owntrace scan --dry-run

# 6. Run the scan
owntrace scan                       # exit code 5 = CONFIRMED findings exist

# 7. Inspect results and reports
owntrace results list
owntrace results show --finding F-XXXXXXXX
owntrace results integrity          # verify evidence SHA-256 hashes
open owntrace-data/reports/report.html
```

A complete worked example — including the exact `owntrace.yaml` and
`auth.yaml` — lives in [`examples/vulnerable-demo/`](examples/vulnerable-demo/).

---

## The workflow in depth

### 1. Declare the scope (deny-by-default)

Nothing outside `scope.targets` is ever contacted. Subdomains are *not*
auto-authorized. Path includes/excludes, method allowlists, per-target and
global request budgets, blocked (destructive) path patterns, rate limits and
concurrency are all enforced **in code** before every request.

```yaml
scope:
  targets:
    - host: "api.example.com"
      schemes: ["https"]
      include_paths: ["/api/"]
      exclude_paths: ["/api/admin/logout"]
      allowed_methods: ["GET", "HEAD", "OPTIONS"]
      max_requests: 500
  global_allowed_methods: ["GET", "HEAD", "OPTIONS"]
  max_requests_total: 2000
```

### 2. Define independent test identities

At minimum **two** profiles that represent **different real users**. OWNTRACE
verifies identity separation by probing each profile against a configured
identity endpoint and comparing the resolved identities:

```yaml
# auth.yaml  (chmod 600, gitignored — credentials never enter reports)
auth:
  profiles:
    - name: userA
      type: bearer
      token: "{{ env OT_USERA_TOKEN }}"
      identity: { endpoint: "https://api.example.com/api/v1/me", method: "GET", field: "user.id" }
    - name: userB
      type: bearer
      token: "{{ env OT_USERB_TOKEN }}"
      identity: { endpoint: "https://api.example.com/api/v1/me", method: "GET", field: "user.id" }
```

If separation cannot be verified, cross-account testing is aborted rather
than producing meaningless verdicts.

### 3. Map object ownership

Ownership evidence comes from three sources, in decreasing quality:

| Source | State | How |
|---|---|---|
| Controlled creation workflow | `confirmed` | OWNTRACE creates disposable test objects as each profile (opt-in, requires `allow_write_methods`) |
| Configuration | `declared` | You declare "object X belongs to profile userA" |
| Listing membership / tagged traffic | `inferred` | The object appears in a profile's own collection, or in profile-tagged HAR traffic |
| No evidence | `unknown` | Never supports a CONFIRMED verdict |

### 4. Test — the verification battery

For every object × endpoint the engine runs:

1. **Owner baseline** — the owner must successfully retrieve the object.
2. **Negative control** — a *nonexistent* object of the same shape, requested
   as the attacker, establishes the app's real denial behavior.
3. **Non-owner access** — a different verified identity requests the object.
4. **Decision matrix** — 401/403 → `REJECTED`; generic 404 matching the
   negative control → `REJECTED`; empty/generic 200 (decoy endpoints that
   respond identically for nonexistent objects) → `REJECTED`; data returned
   to a non-owner → candidate `CONFIRMED`.
5. **Cache analysis** — cache-busted re-request detects cache-served artifacts.
6. **Public-content probe** — if the anonymous request gets the same data,
   the content is public (an *exposure*), not a horizontal authorization failure.
7. **Repeatability** — the access must reproduce on every repeat.

A finding reaches `CONFIRMED` **only** when: target in scope, resource known,
ownership backed by evidence, owner baseline succeeds, a *distinct* verified
identity receives the object's data, the response demonstrably contains that
object's fields, and the result reproduces without cache artifacts. Anything
less becomes `SUSPECTED` or `INCONCLUSIVE` with the missing condition named.

Every state transition (`DISCOVERED → CANDIDATE → TESTING → CONFIRMED /
SUSPECTED / INCONCLUSIVE / REJECTED / ERROR`) is recorded with a reason and
evidence reference.

### 5. Report and review

Reports distinguish CONFIRMED / SUSPECTED / INCONCLUSIVE / REJECTED / ERROR,
include scope, methodology, ownership evidence, reproduction steps with
redacted credentials, remediation guidance, and an explicit limitations
section. **They are written for human review** — review before submitting
anything to a bug bounty platform.

---

## CLI overview

```
owntrace version                    # build info
owntrace init                       # scaffold owntrace.yaml + auth.yaml
owntrace config validate|show       # validate; show (always redacted)
owntrace scope validate|check       # scope helpers; check one URL, no request
owntrace auth add|list|check        # profiles; verify identity separation
owntrace discover urls|har|openapi|crawl    # endpoint inventory only
owntrace scan -u https://authorized.example --report=html   # primary workflow: full pipeline (exit 5 = CONFIRMED)
owntrace scan [--dry-run] [--json] [--config path]   # configured-project form
owntrace verify [--finding ID] [--state SUSPECTED]  # re-run controls
owntrace report [--formats json,markdown,html,csv]
owntrace results list|show|sessions|integrity|cleanup
```

Exit codes: `0` ok · `1` usage · `2` config · `3` scope violation ·
`4` runtime error · `5` CONFIRMED findings (CI-friendly).

Full reference: [docs/cli.md](docs/cli.md) · Configuration:
[docs/configuration.md](docs/configuration.md)

---

## Detection quality: the test matrix

OWNTRACE's integration tests assert the detection matrix itself — against a
bundled deliberately vulnerable application (`cmd/mockapp`) containing both
vulnerable and correctly protected endpoints:

| Scenario | Mock endpoint | Expected verdict |
|---|---|---|
| Vulnerable horizontal IDOR | `GET /api/v1/orders/{id}` | **CONFIRMED** (horizontal) |
| Correctly protected object | `GET /api/v1/invoices/{id}` | **REJECTED** |
| Authenticated IDOR, anon blocked | `GET /api/v1/documents/{id}` | **CONFIRMED** |
| Fully anonymous object access | `GET /api/v1/receipts/{id}` | **CONFIRMED** (anonymous category) |
| Vertical role bypass | `GET /api/v1/admin/stats` | **CONFIRMED** (vertical) |
| Admin-only enforced | `GET /api/v1/admin/users/{id}` | **REJECTED** |
| Cross-tenant breach | `GET /api/v1/tenants/{tid}/files/{fid}` | **CONFIRMED** (cross-tenant) |
| Nested resource, protected | `GET /api/v1/invoices/{id}/payments` | **REJECTED** |
| Nested resource, vulnerable | `GET /api/v1/orders/{id}/notes` | **CONFIRMED** (nested) |
| Decoy: 200 + echoed id, no object | `GET /api/v1/echo/{id}` | **REJECTED** |
| Cache serves owner body to others | `GET /api/v1/cached-docs/{id}` | **SUSPECTED** (cache control FAILED) |
| Out-of-scope redirect | `/redirect/external` | **blocked, never followed** |
| Same identity in two profiles | both profiles → same `user.id` | testing **aborted** |
| Unknown ownership | — | never **CONFIRMED** |

Run the suite yourself: `go test ./...` (add `-race`).

---

## Limitations (read before trusting verdicts)

- OWNTRACE tests what it can observe with the profiles and objects **you**
  configure. Access rules depending on request state, time, or unseen
  parameters may be missed or misjudged.
- `INCONCLUSIVE` usually means a broken baseline (wrong identifier,
  misconfigured profile) — fix the configuration, not the app.
- Decoy detection and similarity thresholds are heuristics. Anything not
  clearly reproducible with full object data stays below CONFIRMED.
- **No tool finds every IDOR.** Workflows that need application-specific
  knowledge (state-changing operations, multi-step flows) require human
  configuration — see [docs/cross-account-testing.md](docs/cross-account-testing.md).
- Anonymous-access findings describe exposure of *your configured test
  objects only*; OWNTRACE never enumerates real users' data.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/installation.md](docs/installation.md) | Building, reproducibility, versioning |
| [docs/cli.md](docs/cli.md) | Every command, flag and exit code |
| [docs/configuration.md](docs/configuration.md) | Full configuration reference |
| [docs/authentication.md](docs/authentication.md) | Profiles, secret hygiene, identity separation |
| [docs/scope-and-safety.md](docs/scope-and-safety.md) | The safety engine and authorization boundaries |
| [docs/discovery.md](docs/discovery.md) | Seeds, HAR, OpenAPI/Swagger, crawling |
| [docs/cross-account-testing.md](docs/cross-account-testing.md) | The verification battery in detail |
| [docs/evidence-and-reporting.md](docs/evidence-and-reporting.md) | Evidence format, integrity, report interpretation |
| [docs/architecture.md](docs/architecture.md) | Module map and data flow |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common errors and fixes |

## Contributing & support

- [CONTRIBUTING.md](CONTRIBUTING.md) — development workflow, regression policy
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities in OWNTRACE itself
- [CHANGELOG.md](CHANGELOG.md) — release history

## License

Distributed under the [MIT License](LICENSE) — Copyright (c) 2026 Lutfifakee.
