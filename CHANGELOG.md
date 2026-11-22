# Changelog

All notable changes to OWNTRACE are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — Initial Release (owner-designated, 2026-11-21)

The first complete public release of OWNTRACE, per the project owner's
explicit version decision. It contains every mandatory capability of the
product specification — the same audited implementation that passed the
canonical-spec conformance cycle (12 mandatory gaps implemented, 4 defects
found and fixed with regression tests, full quality gates green including
race and cross-platform builds).

Everything listed under the historical internal milestones below ships in
this release. The internal milestone gates (v0.2.0–v1.0.0) were development
traceability checkpoints, not published releases; their artifacts are
preserved under `download/release-gates/` as historical records.

### Highlights of the initial release
- CLI-first, offline, single-command assessment:
  `owntrace scan -u https://authorized.example --report=html`
- Deny-by-default scope with hop-by-hop redirect validation and a
  metadata-address dial guard; independent auth profiles with mandatory
  identity separation; ownership intelligence (declared/created/inferred)
  with the invariant that inferred/unknown never confirm.
- Evidence-based verification through one central policy gate: negative
  controls, public-content probes, cache analysis, repeatability and
  evidence persistence are mandatory per category — including the adjacent
  authorization categories BFLA, BOPLA and sensitive business flows.
- Stateful workflow engine (§25) and a GraphQL adapter (§26) with
  partial-data analysis; mutations stay write-gated.
- Tamper-evident per-session evidence hash chains; export/import bundles
  with bundle-level integrity digests verified on BOTH sides; backup,
  restore, retention, interrupted-session recovery; database files enforced
  0600.
- Findings with severity (no fabricated CVSS), CWE + OWASP API Top-10
  mappings, triage notes, accepted-risk and suppression with justification.
- Coverage accounting (planned vs executed vs safety-skipped), JSON/
  Markdown/HTML/CSV reports with export-time evidence validation, exit
  code 5 for CI, `doctor`/`history`/`help`/`verify`/`results` command
  families, explicit proxy support.

### Historical note on internal version milestones
The sections below record the development milestone gates truthfully. The
former v1.0.0 internal gate is superseded by this owner-designated v0.1.0
initial release; its artifacts are retained unchanged for audit history.

## [1.0.0] — Internal Milestone Gate: Mature Stable Release (historical)

### Added — canonical-spec conformance cycle (§52–§55: mandatory capabilities
found missing by the spec-driven audit were implemented immediately, per §55)
- **Canonical CLI surface:** `scan -u/--target` with path-prefix scope
  narrowing, `--report`, `--openapi`, `--har`, `--workflow`, `--profile`,
  `--list`, `--scope`, `--output`, `--no-discover` (inventory reuse with
  stale/scope rejection), `discover --target`, `report --format`, `help`,
  `history`, and the §41 `doctor` command (config, credentials, identity
  probes, scope, inputs, database, permissions, network, protocol matrix —
  never contacts targets).
- **Adjacent authorization categories:** BFLA (function-level battery with
  declared permissions + role context), BOPLA (declared restricted
  properties with an owner-baseline fabrication guard), and sensitive
  business-flow bypass — separate finding types, each with its own §29
  verification battery through the central gate.
- **Stateful workflow engine (§25):** operator flow files with state
  substitution, extraction, expectation-gated steps, negative controls
  (decoy flows abort), and best-effort cleanup; flow-created objects feed
  confirmed ownership; unauthorized re-execution drives the business-flow
  battery.
- **GraphQL adapter (§26):** operations harvested from HAR traffic,
  object-level node/variables battery with negative control, partial-data
  analysis, cache analysis and repeatability; mutation testing stays gated
  by `allow_write_methods`.
- **Finding triage (§34):** severity with default/operator source (no
  fabricated CVSS), CWE + OWASP API Top-10 mappings, triage notes,
  accepted-risk and suppression with justification (schema migration v3).
- **Storage transfer (§35–36):** `results export/import` bundles with
  fail-closed evidence verification on BOTH sides, `results backup/restore`
  (validated on a scratch copy, rollback copy preserved), database files
  enforced to 0600 regardless of umask.
- **Proxy support (§30):** `network.proxy_url` with the dial guard still
  enforced on every resolved target address.
- **Coverage accounting (§33):** planned vs executed vs safety-skipped
  checks in the scan summary.

### Fixed — canonical-spec audit defect ledger
- Evidence ID sequences restarted on a new process over an existing
  database (colliding rows); the counter is now persisted and recovered.
- Workflow findings and ownership records pointed at negative-control URLs;
  object surfaces now resolve through real flow steps.
- Workflow state extraction read evidence-redacted bodies; the engine now
  carries an in-memory raw body channel (never serialized) for exact value
  replay, while evidence/report/exports stay redacted.

Internal development milestone (not a published release). The complete
implementation of the OWNTRACE product vision. v1.0.0 was a
stability and trustworthiness release on top of the v0.6.0 feature set —
nothing was removed; all verdict discipline from v0.2.0+ is preserved.

### Added — v0.7.0 Evidence, Storage & Reporting
- **Evidence validation at export time:** every evidence record embedded in
  a report is hash-verified during generation; failures are surfaced in a
  prominent report section (and the JSON `evidence_integrity_failures`
  field) with untrusted-content guidance — reports never silently embed
  tampered evidence.
- Authorization consistency analysis surfaced in Markdown/JSON reports.

### Validated — v0.8.0 CLI & Usability
- Direct CLI behavioral suite: exit codes (0/1/2/3/4/5), help completeness,
  config/auth redaction guarantees, auth-file permission enforcement.
- End-to-end CLI workflows (init → dry-run → scan → results → report →
  integrity) executed against the bundled vulnerable lab.

### Validated — v0.9.0 Release Candidate
- Dependency vulnerability review (`govulncheck ./...`): clean.
- Cross-platform artifacts (linux amd64/arm64, darwin amd64/arm64,
  windows amd64) with SHA-256 checksums; clean-extract rebuild passes the
  full suite on the pinned toolchain.
- Fuzz sessions for all untrusted-input parsers: no crashes.
- Performance benchmarks recorded for redaction, similarity, hashing and
  scope checks.

### v1.0.0 acceptance gate (§14)
All 16 acceptance conditions verified with executed commands and stored
artifacts; see `FINAL-REPORT.md` (traceability matrix, defect ledger,
security verification, test results, limitations, verdict).

## [0.6.0] — Authentication & Ownership Intelligence, Safety Hardening, Coverage

(Contains the completed scopes of milestones v0.3.0–v0.6.0; boundaries were
consolidated because the scopes landed in one development window — see
docs/milestones.md.)

### Added — v0.3.0 Authentication & Ownership Intelligence
- Direct mapper tests: declared mappings, controlled creation workflows
  (CONFIRMED ownership), listing-membership inference (INFERRED), and
  out-of-scope creation refusal.
- Expired/invalid owner tokens yield INCONCLUSIVE baselines — never false
  verdicts (session lifecycle regression test).

### Added — v0.4.0 Discovery & API Understanding
- Native fuzz targets for the untrusted-input parsers (HAR, OpenAPI/Swagger,
  URL templating) with seed corpora; 45s fuzz sessions completed with zero
  crashes; hostile-input seed cases added as regression tests.

### Added — v0.5.0 Scope & Safety Hardening
- **Dial guard:** hostnames are re-resolved per dial and every resolved IP is
  validated; link-local unicast addresses (IPv4 169.254.0.0/16 incl. cloud
  metadata, IPv6 fe80::/10) are refused UNCONDITIONALLY — DNS rebinding
  toward metadata endpoints is impossible even when the hostname is in
  scope. IP-literal metadata targets are also refused. Private/loopback
  targets remain the operator's explicit scope choice.

### Added — v0.6.0 Authorization Testing Coverage
- **Role matrix:** every privileged endpoint is tested against EVERY
  non-privileged profile (per-role findings with requester attribution).
- **Authorization consistency analysis** in reports: resource types with
  mixed enforcement outcomes across endpoints are flagged as partial-
  enforcement patterns.

### Fixed
- Mock lab fixtures now use realistic lowercase JSON field names
  (`id`, `owner`, ...) — collection mining and object extraction operate on
  realistic API shapes.

### Verification

- 152 tests passing / 0 failing; `go test -race ./...` green (18 packages).
- `govulncheck ./...`: no vulnerabilities.
- Fuzz sessions (45s total): no crashes.

## [0.2.0] — Verification Engine Integrity

### Fixed — security correctness (audit leads A–H)

- **Central confirmation gate (§4.3):** every verification category now
  routes its verdict through a single policy (`verification.Candidate
  .Evaluate`). CONFIRMED is emitted only when all mandatory prerequisites
  hold; the policy is exhaustively unit-tested — each missing prerequisite
  is proven to block confirmation.
- **Identity separation is now an unconditional invariant (lead B):**
  profiles that resolve to the SAME principal can never produce CONFIRMED,
  even with `require_identity_separation: false`. Unverified identities
  (missing/failed probes) cap findings at SUSPECTED. The configuration flag
  now only controls whether the run aborts early.
- **Negative controls must execute (lead C):** a negative control that
  fails, times out, or errors no longer counts as a passing control; without
  it, CONFIRMED is impossible.
- **Public-content probe is mandatory (lead D):** a probe that cannot
  execute blocks CONFIRMED; a probe that reproduces the object data without
  credentials REJECTS the horizontal finding (public exposure).
- **Cache analysis is mandatory for CONFIRMED (lead D):** disabling
  `cache_bust` no longer allows confirmation. A cache that ignores busters
  (headers present + bust reproduced) cannot be ruled out → SUSPECTED.
- **Evidence persistence is required (lead E):** capture failures are
  propagated; a finding whose required evidence was not stored can never
  become CONFIRMED.
- **Ownership invariant tightened (lead F):** inferred and unknown
  ownership can NEVER support CONFIRMED (`AllowedForConfirmed` now excludes
  inferred); the confirmation floor accepts only `declared|confirmed`
  (validated at load).
- **Vertical verification hardened (lead A):** role bypass confirmation now
  requires executed negative control (nonexistent admin path), public-
  content probe (generic admin pages are REJECTED), cache analysis,
  repeatability, verified distinct roles and persisted evidence.
- **Registry lookup determinism:** `ownership.Lookup` returns the highest-
  quality matching record instead of a map-order-dependent one; the lookup
  key format mismatch with the record key was fixed.
- **CLI unknown subcommands** now exit 1 (usage) instead of silently
  printing help.

### Added

- **Tamper-evident evidence chains (lead G):** per-session hash chains
  (`prev_sha256` links + session `evidence_head`), schema migration v2;
  `results integrity` now detects payload modification, record deletion,
  forged insertion and newest-record removal. Documented honestly as
  tamper-EVIDENT (database-write attacker can rebuild a chain; external
  anchoring is a documented future hardening).
- **Direct test coverage (lead H):** new suites for `internal/evidence`
  (canonicalization, tampering, chain integrity, concurrent capture),
  `internal/finding` (state machine, controls, IDs, redaction),
  `internal/ownership` (invariant, merge/escalation semantics),
  `internal/cli` (exit codes, help, redaction, auth-file permissions).
- **Mock-app traps (§9.2):** soft-404 endpoint, path-keyed cache that
  ignores busters, admin-looking public page.
- **§9.3 security regression suite:** 10 engine-level tests proving
  HTTP-200-only, similarity-only, reflected-identifier, same-identity,
  missing-negative-control, failed-probe, missing-evidence, tampered-
  evidence and cache-artifact scenarios cannot confirm — each exercised
  with the corresponding weakening option disabled.

### Verification

- 137 tests passing / 0 failing (v0.1.0 baseline: 97).
- `go test -race ./...` green across all 19 packages.
- Full E2E detection matrix preserved: all vulnerable scenarios still
  CONFIRM; protected, decoy, cache and public traps still reject.

## [0.1.0] — initial release

### Added

**Core pipeline**
- `scan` command: discovery → identity separation → ownership mapping →
  cross-account verification → evidence capture → SQLite persistence →
  report generation, with bounded concurrency and graceful Ctrl-C shutdown.
- Deny-by-default scope engine: explicit host allowlist, scheme rules,
  path include/exclude, per-target and global method allowlists, blocked
  destructive-path patterns, per-target and global request budgets,
  subdomain policy (off by default).
- Safety engine: global/per-host rate limiting, bounded concurrency,
  write-method gating (`allow_write_methods`), destructive-path refusal,
  retry ceilings, cancellation fail-safe (no scope configured ⇒ no requests).
- Controlled HTTP client: hop-by-hop redirect scope validation,
  bounded response reads with truncation flags, credential redaction on
  capture, transport-error retry honoring limits.

**Discovery**
- Seed URLs, HAR 1.2 parsing (with profile-tag attribution header),
  OpenAPI 3.x and Swagger 2.x (local `$ref` resolution, security-scheme
  mapping, body template synthesis), scope-bound HTML/JS crawler
  (GET-only, depth and page budgets).
- Endpoint normalization with identifier templating and provenance-preserving
  deduplication.

**Authentication**
- Independent profiles: bearer, JWT, header, cookie, basic, anonymous.
- Identity-separation verification via configurable identity probes;
  indistinct identities abort cross-account testing when required.
- Secrets from `auth.yaml` (0600, gitignored) or `{{ env VAR }}` references.

**Ownership**
- Ownership registry with states confirmed / declared / inferred / unknown.
- User-declared mappings, controlled creation workflows (opt-in), and
  listing-membership inference from configured collection endpoints and
  profile-tagged HAR traffic.
- Unknown ownership can never support a CONFIRMED verdict.

**Verification engine**
- Owner baseline, negative control (nonexistent object), non-owner access,
  anonymous access, vertical role tests, nested-resource categorization,
  cross-tenant tests.
- Decision matrix with: identifier-presence check, body similarity,
  owner-data field overlap, decoy detection (2xx for nonexistent objects),
  cache-bust analysis, public-content probe, repeatability control,
  identity-separation gate, ownership-floor gate.
- Explicit finding state machine (DISCOVERED, CANDIDATE, TESTING, CONFIRMED,
  SUSPECTED, INCONCLUSIVE, REJECTED, ERROR) with reasoned transitions.

**Evidence & storage**
- Append-only evidence records, canonical-JSON SHA-256 integrity,
  `results integrity` verification command.
- Versioned SQLite schema with migrations, session lifecycle, interrupted
  session recovery, retention cleanup.
- Credential redaction at capture boundaries; `config show` always redacted.

**Reporting**
- JSON, Markdown, HTML (responsive), CSV outputs; verdict-segregated sections,
  scope and methodology documentation, reproduction steps with redacted
  credentials, explicit limitations section; no fabricated CVSS/severity.

**CLI**
- `version`, `init`, `config validate|show`, `scope validate|check`,
  `auth add|list|check`, `discover urls|har|openapi|crawl`, `scan [--dry-run]`,
  `verify`, `report`, `results list|show|sessions|integrity|cleanup`.
- Predictable exit codes (0/1/2/3/4/5); machine-readable `--json` outputs;
  `--help` with examples on every command.

**Testing & QA**
- Unit tests for all core packages; integration matrix against the bundled
  vulnerable lab application (`cmd/mockapp`): 7 confirmed categories,
  5 protected scenarios rejected, decoy and cache false-positive filters,
  identity-separation abort, anonymous handling.
- Security tests: scope-escape via redirect (never contacted), destructive
  request refusal, config redaction, malformed HAR/OpenAPI handling,
  concurrent cancellation, oversized/garbage responses.
- Race-detector clean (`go test -race ./...`), `go vet` clean, `gofmt` clean.
- Benchmarks for redaction, similarity, canonical hashing, scope checks.

### Known limitations
- Detection depends on configured test identities and objects; stateful or
  multi-step authorization flows need manual configuration.
- Anonymous-access findings cover only the configured test objects.
- No browser automation; JS-heavy applications should be imported via HAR.
