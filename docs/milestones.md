> **Version designation (2026-11-21):** the milestones below are internal
> development gates used for traceability. The owner has designated
> **v0.1.0** as the first complete public release; the former v1.0.0 gate
> artifacts remain preserved as history and are superseded by the v0.1.0
> release candidate.

# OWNTRACE Milestone Ledger

One repository, versioned milestones, local development. Git tags and GitHub
Releases are created only after owner publication approval (Master Prompt
§12); until then, milestones are recorded here with reproducible local
artifacts under `download/release-gates/<version>/`.

---

## v0.1.0 — inherited baseline audit

**Baseline preserved:** `baseline/owntrace-v0.1.0-inherited.tar.gz`
(SHA-256 `82b89ad47683033bec0b8b7a9b23ddc645ab752f5c2fa608d7fa592e09f43118`).

Owner-side baseline checks (independently executed): `go mod verify`,
`gofmt -l`, `go vet ./...`, `go test ./...`, `go test -race ./...` — all
passed. Passing gates do not establish verdict correctness, so the master
prompt's eight audit leads were independently verified against the code:

| Lead | Finding | Verdict on inherited code |
|---|---|---|
| A — vertical verification | CONFIRMED from similarity alone; no decoy gate, no public probe, no cache analysis | **defective** |
| B — identity separation | `require_identity_separation: false` allowed proven same-identity CONFIRMED | **defective** |
| C — negative controls | failed/nil negative control silently skipped; CONFIRMED proceeded without it | **defective** |
| D — public/cache analysis | probes skipped when config disabled or errored; cache headers + reproduced bust not distinguished | **defective** |
| E — evidence persistence | capture errors swallowed at `engine.go:126`; CONFIRMED with unpersisted evidence possible | **defective** |
| F — ownership rules | `AllowedForConfirmed` included inferred; floor unvalidated (`inferred` floor possible) | **defective** |
| G — evidence integrity | bare SHA-256; no chaining/manifest; modification-with-digest undetectable | **insufficient** |
| H — test coverage | `internal/evidence`, `internal/finding`, `internal/ownership`, `internal/cli` had zero direct tests | **gap** |

All findings fixed in v0.2.0 with regression tests (below).

---

## v0.2.0 — Verification Engine Integrity (COMPLETE)

**Theme:** the confirmation engine enforces every mandatory proof condition
through one central gate; false-positive traps are proven with the weakening
options disabled.

### Defect ledger (all fixed with regression tests)

| # | Defect | Root cause | Fix | Regression test |
|---|---|---|---|---|
| 1 | Same-identity profiles could CONFIRM | downgrade gate conditioned on config flag | identity invariant unconditional in policy | `TestSecSameIdentityCannotConfirmEvenWhenConfigDisabled` |
| 2 | Missing negative control allowed CONFIRMED | control skipped on failure; classify ignored absence | `NegativeControlDone` prerequisite | `TestSecMissingNegativeControlCannotConfirm` |
| 3 | Failed public probe allowed CONFIRMED | probe skipped on error | `PublicProbeDone` prerequisite | policy tests; `TestSecPublicAdminPageRejected` |
| 4 | Disabled cache analysis allowed CONFIRMED | `CacheBust` flag gated the control | analysis mandatory for candidates; flag=false ⇒ cannot confirm | `TestSecCacheAnalysisDisabledStillBlocksConfirmation` |
| 5 | Buster-ignoring cache indistinguishable | bust-reproduced treated as PASS unconditionally | headers-present + reproduced ⇒ cannot rule out ⇒ SUSPECTED | `TestSecCacheIgnoringBustersCannotConfirm` |
| 6 | CONFIRMED with unpersisted evidence | capture errors swallowed | evidence errors propagate; `EvidencePersisted` prerequisite | `TestSecEvidencePersistenceFailureCannotConfirm` |
| 7 | Inferred ownership could confirm | `AllowedForConfirmed` included inferred | invariant restricted to confirmed/declared; floor validated | `TestAllowedForConfirmedInvariant`; config validation |
| 8 | Evidence tamper-evidence limited to per-record hash | no chaining/manifest | per-session hash chains + head; migration v2 | storage chain tamper tests |
| 9 | Vertical bypass from generic pages | no decoy/public/cache controls in vertical path | vertical routed through central policy with all controls | `TestSecPublicAdminPageRejected` vs `TestSecGenuineVerticalBypassStillConfirms` |
| 10 | `ownership.Lookup` never matched records | key format drift after key added endpoint path; map-order dependence | structural match + deterministic best-match | `TestUpsertMergesWithStateRanking` (caught it) |
| 11 | Unknown CLI subcommand exited 0 | container command printed help unconditionally | leftover non-flag args ⇒ usage error (exit 1) | `TestUnknownCommandExitsUsage` |
| 12 | Engine panic on nil wire error (baseline failure path) | eager `.Error()` on nil error | nil-safe `wireErrText` | scan suite after fix |
| 13 | **Release-blocking:** `.gitignore` pattern `owntrace` (unanchored) also matched `cmd/owntrace/` — `main.go` silently excluded from any future `git add`; a fresh clone would not build | binary-name pattern without root anchor | patterns root-anchored to `/owntrace`, `/owntrace.exe`; tree audited for other silently-ignored sources (none) | `git check-ignore owntrace/cmd/owntrace/main.go` → exit 1; clean-extract archive carries main.go |
| 14 | Release binaries falsely embedded VCS metadata (`vcs.revision=<enclosing workspace commit>`) — built without `-buildvcs=false` inside a git repo, implying a project commit that does not exist | default go-build VCS stamping | `-buildvcs=false` added to build-release.sh; all five regenerated binaries verified with zero `vcs.*` buildinfo entries | found during the v1.0.0 release-validation cycle (2026-11-17); previous gate preserved at download/release-gates/audit-archive/v1.0.0-previous-20261117 |

### Gate results (executed)

```
gofmt -l ./cmd ./internal   → (empty)
go vet ./...                → clean
go test ./...               → 137 PASS / 0 FAIL  (baseline: 97)
go test -race ./...         → ok, all 19 packages
E2E detection matrix        → vulnerable scenarios CONFIRM, traps REJECT/SUSPECT
Evidence chain tamper tests → payload tamper, deletion, head removal detected
```

### Artifacts

`download/release-gates/v0.2.0/` — source `.tar.gz` + `.zip`, five platform
binaries, `SHA256SUMS`, `RELEASE-NOTES.md`. **No git tag/commit created**
(owner authorization required per §12).

---

## v0.6.0 — Coverage & Hardening (COMPLETE, consolidated with v0.3.0–v0.5.0)

Consolidation note: the v0.3.0–v0.5.0 scopes landed in one development
window and shipped together in this gate (boundary adjustment permitted by
the master prompt; no artificial versions).

- **v0.3.0:** direct mapper tests (declared/created/inferred ownership,
  out-of-scope creation refusal); expired owner tokens ⇒ INCONCLUSIVE.
- **v0.4.0:** fuzz targets for HAR/OpenAPI/URL parsers; hostile seed corpus;
  45s fuzz sessions crash-free.
- **v0.5.0:** dial guard — unconditional link-local/metadata blocklist with
  per-dial re-resolution; IP-literal metadata refused.
- **v0.6.0:** role matrix (endpoint × every non-admin profile) and
  authorization consistency analysis in reports.
- Fixed during the window: mock fixtures with realistic JSON tags;
  `ownership.Lookup` determinism (found by new direct tests); CLI unknown-
  subcommand exit code.
- Gate: 152 PASS / 0 FAIL; race green; govulncheck clean; artifacts +
  clean-extract rebuild verified. Artifacts: release-gates/v0.6.0.

## v0.7.0 — Evidence, Storage & Reporting (COMPLETE)

- Export-time evidence validation: reports verify every embedded evidence
  record at generation; failures surface in a dedicated section with
  untrusted-content guidance (`evidence_integrity_failures` in JSON).

## v0.8.0 — CLI & Usability (VALIDATED)

- Direct CLI behavioral suite (exit codes 0/1/2/3, help completeness,
  redaction guarantees, auth-file permission enforcement); E2E workflows
  (init → dry-run → scan → results → report → integrity) executed.

## v0.9.0 — Release Candidate (COMPLETE)

- `govulncheck ./...`: clean. Cross-platform artifacts + checksums verified.
- Benchmarks recorded; reproducible builds verified; clean-extract rebuilds
  pass the full suite for v0.2.0, v0.6.0 and v1.0.0.

## v1.0.0 — Mature Stable Release (COMPLETE)

- §14 acceptance gate: all 16 conditions verified (see FINAL-REPORT.md).
- 154 PASS / 0 FAIL; race green (18 packages); fuzz sessions clean.
- Verdict: **READY FOR OWNER ACCEPTANCE**. Artifacts: release-gates/v1.0.0.

## Roadmap status

- All milestone scopes complete; publication (git tags + GitHub Releases)
  awaits owner authorization (§12).
