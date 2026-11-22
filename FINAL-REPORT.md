> **Historical record.** This report documents the v1.0.0-cycle audit
> truthfully and is preserved as history. On 2026-11-21 the owner designated
> v0.1.0 as the first complete public release; the same audited
> implementation now ships as v0.1.0 (see CHANGELOG [0.1.0] and
> download/release-gates/v0.1.0).

# OWNTRACE Final Report — v1.0.0 Autonomous Development Lifecycle

**Project:** OWNTRACE — Automated Object Ownership & Authorization Testing
**Repository:** `Lutfifakee-Project/owntrace` (one repository, versioned milestones)
**Final version:** 1.0.0 · **Audit date:** 2026-11-17
**Toolchain:** Go 1.27.4, linux/amd64 (2 vCPU / 4 GB RAM)
**Final verdict:** **READY FOR OWNER ACCEPTANCE**

Per Master Prompt §12: **no commits, tags, pushes or releases have been
created.** All milestones were developed and gated locally; release-gate
artifacts (source archives, checksums, release notes, five platform
binaries) are prepared under `download/release-gates/` for the owner to
review and publish after acceptance.

---

## A. Executive summary

- **Product identity:** OWNTRACE — Discover. Compare. Verify. CLI-first,
  offline-capable Go tool for evidence-based IDOR/BOLA testing.
- **What is genuinely implemented:** deny-by-default scope enforcement with
  hop-by-hop redirect validation and a metadata-address dial guard; a
  central, exhaustively-tested confirmation policy that no verification
  category can bypass; unconditional identity-separation invariant; mandatory
  fail-closed negative controls, public-content probes and cache analysis;
  evidence-required confirmation with per-session tamper-evident hash chains;
  ownership states (confirmed/declared/inferred/unknown) with the invariant
  that inferred/unknown never confirm; discovery from URLs, HAR 1.2,
  OpenAPI 3.x/Swagger 2.0 and scope-bound crawling with fuzz-hardened
  parsers; role-matrix vertical testing; JSON/Markdown/HTML/CSV reports with
  export-time evidence validation; SQLite persistence with migrations,
  retention and interrupted-session recovery.
- **Verdict basis:** 154 tests passing / 0 failing; `go test -race ./...`
  green (18 packages); `govulncheck` clean; fuzz sessions crash-free;
  reproducible builds; clean-extract rebuild passes the full suite.

## B. Version history

| Version | Scope | Outcome | Evidence |
|---|---|---|---|
| v0.1.0 (inherited) | Baseline audit | 8 audit leads verified: 6 defective, 1 insufficient, 1 coverage gap; baseline archived (SHA-256 `82b89ad4…`) | docs/milestones.md |
| v0.2.0 | Verification engine integrity | Central confirmation gate; leads A–F fixed; chains (G); direct tests (H); 97→137 tests | release-gates/v0.2.0 |
| v0.3.0 | Auth & ownership intelligence | Mapper tests (declared/created/inferred/out-of-scope refusal); expired-token ⇒ INCONCLUSIVE | release-gates/v0.6.0 |
| v0.4.0 | Discovery understanding | 3 fuzz targets + hostile seeds; 45s fuzz sessions crash-free | release-gates/v0.6.0 |
| v0.5.0 | Scope & safety hardening | Dial guard: unconditional link-local/metadata blocklist, per-dial re-resolution | release-gates/v0.6.0 |
| v0.6.0 | Coverage | Role matrix (endpoint × every non-admin profile); consistency analysis in reports; realistic JSON fixtures | release-gates/v0.6.0 |
| v0.7.0 | Evidence/storage/reporting | Export-time evidence validation with untrusted-content warnings | release-gates/v1.0.0 |
| v0.8.0 | CLI & usability | Direct CLI behavior suite (exit codes, help, redaction, permissions); E2E workflows executed | release-gates/v1.0.0 |
| v0.9.0 | Release candidate | govulncheck clean; cross-platform artifacts; reproducible builds; benchmarks recorded | release-gates/v1.0.0 |
| v1.0.0 | Mature stable release | §14 acceptance gate: all 16 conditions pass | this report |

Milestone boundary note: v0.3.0–v0.6.0 landed in one development window and
were consolidated into the v0.6.0 gate; the ledger above maps each scope to
its version. No artificial versions were created.

## C. Product capability matrix

See `docs/acceptance-matrix.md` (42 requirements, classified verified /
partial / missing with test evidence). Headline rows: all confirmation,
ownership, identity, evidence, scope-safety and CLI requirements are
**verified**; two documented gaps remain (24: tamper-PROOF anchoring;
38–39 partially: fuzz targets exist, CI publication pending owner
authorization).

## D. Security verification

| Invariant | Enforcement | Proof |
|---|---|---|
| CONFIRMED is proof-based (§4.1: 12 prerequisites) | `verification.Candidate.Evaluate` — the only CONFIRMED emission path | `TestPolicyEveryMissingPrerequisiteBlocksConfirmation` (12 cases) |
| Same identity never confirms | unconditional policy check | `TestSecSameIdentityCannotConfirmEvenWhenConfigDisabled` |
| Ownership: inferred/unknown never confirm | `ownership.AllowedForConfirmed` (no config input) + floor validation | `TestAllowedForConfirmedInvariant`; config validation |
| Negative control mandatory, fail-closed | `NegativeControlDone` prerequisite | `TestSecMissingNegativeControlCannotConfirm` |
| Public-content probe mandatory, fail-closed | `PublicProbeDone` prerequisite | `TestSecPublicAdminPageRejected` |
| Cache analysis mandatory; buster-ignoring cache blocked | `CacheAnalysisDone` + header analysis | `TestSecCacheAnalysisDisabledStillBlocksConfirmation`, `TestSecCacheIgnoringBustersCannotConfirm` |
| Evidence-required confirmation | evidence errors propagate; `EvidencePersisted` prerequisite | `TestSecEvidencePersistenceFailureCannotConfirm` |
| Evidence tamper-EVIDENCE | per-session hash chains + head; payload/link/head checks | storage chain tamper tests (payload, deletion, head) |
| Expired tokens ⇒ INCONCLUSIVE | baseline denial handling | `TestSecExpiredOwnerTokenIsInconclusive` |
| Soft-404 / echo decoys rejected | decoy gate + data-overlap gate | `TestClassifyMatrix`, `TestSecSoft404IsInconclusive`, `TestSecAnonymousEchoDecoyRejected` |
| Scope escapes (incl. redirects) blocked | deny-by-default checker + hop validation | scope suite; Sec-1 |
| Destructive requests blocked by default | method gating + destructive-path denylist | Sec-2 (zero DELETEs sent) |
| Metadata endpoints unreachable | dial guard, unconditional | `TestDialGuardBlocksMetadataResolution`, `TestDialGuardBlocksIPLiteralMetadata` |
| Credentials never persisted/exported | redaction choke point; `config show` always redacted | redact suite; CLI/report leak tests |

§9.3 regression suite: 11 engine-level tests, each exercising the invariant
with its weakening option DISABLED — all pass.

## E. Test results

```
go test ./... -v        → 154 PASS / 0 FAIL
go test -race ./...     → ok (18 packages with tests; version: no tests)
gofmt -l ./cmd ./internal → (empty)
go vet ./...            → clean
govulncheck ./...       → No vulnerabilities found
go test -fuzz=FuzzParseHAR -fuzztime=15s       → PASS (18k execs)
go test -fuzz=FuzzParseOpenAPI -fuzztime=15s   → PASS
go test -fuzz=FuzzBuildFromURL -fuzztime=15s   → PASS
clean-extract rebuild (v1.0.0 source archive)  → build + 18/18 packages ok
```
Environment: Debian 13, Go 1.27.4. Limitations: `go test -fuzz` sessions are
short (15s/target); continuous fuzzing is a CI task pending publication.

## F. Defect ledger

Full ledger in `docs/milestones.md`. Summary of the 17 defects found and
fixed across the lifecycle, each with a regression test: nil-scope safety
panic; evidence sequence race; finding-ID collisions; ownership registry
key-format drift (caught by the new direct tests) + nondeterministic
lookup; nested-path misclassification; auth-file wrapper parsing; time-column
scan type; config floor validation; CLI flag-order resolution and unknown-
subcommand exit code; mock-app reentrant-lock deadlock; non-reentrant test
mutex deadlock (evidence); dialer timeout unit bug; fragile version
assertion in the CLI test; and a release-blocking `.gitignore` defect found
during the publication-handoff audit (unanchored binary-name pattern would
have silently excluded `cmd/owntrace/main.go` from version control — fixed,
tree-wide audited, v1.0.0 source archive re-cut and re-verified); and a false VCS-metadata defect caught by the post-recycle v1.0.0 release-validation cycle (2026-11-17): binaries built without `-buildvcs=false` embedded `vcs.revision` of the enclosing sandbox workspace commit, falsely implying a project git commit — fixed in build-release.sh, all five binaries re-verified with zero `vcs.*` entries, and the complete v1.0.0 gate regenerated (defect 14).

## G. Performance and reliability

| Benchmark | Result |
|---|---|
| Redaction small JSON body (JWT+secrets) | 5,840 ns/op |
| Redaction 64 KiB JSON body | 8.80 ms/op (evidence-capped, off request path) |
| Similarity 64 KiB bodies | 152 µs/op |
| Canonical JSON hash (4 KiB) | 18.5 µs/op |
| Scope check | 7.5 µs/op |
| Endpoint build | 1.4 µs/op |

Reliability: bounded worker pool + semaphore concurrency; per-host rate
limiting; cancellation verified mid-run (Sec-5); interrupted-session
recovery; retry ceilings (transport errors only).

## H. Deliverables

- **Source tree:** `/home/z/my-project/owntrace/` (uncommitted per §12)
- **Baseline:** `baseline/owntrace-v0.1.0-inherited.tar.gz` + SHA-256
- **Release gates:** `download/release-gates/v0.2.0/`, `…/v0.6.0/`,
  `…/v1.0.0/` — each with source `.tar.gz` + `.zip`, 5 platform binaries,
  `SHA256SUMS` (7/7 verified), `RELEASE-NOTES.md`
- **Clean-extract rebuild:** verified for v0.2.0, v0.6.0 and v1.0.0
- **Documentation:** README + 10 docs (installation, CLI, configuration,
  authentication, scope & safety, discovery, cross-account testing,
  evidence & reporting, architecture, troubleshooting) + acceptance matrix
  + milestone ledger + CHANGELOG + SECURITY + CONTRIBUTING + LICENSE
- **Examples:** vulnerable-demo walkthrough (executed end-to-end)
- **CI:** `.github/workflows/ci.yml` (fmt/vet/build/race/bench/smoke)

## I. Outstanding limitations

1. Evidence chains are tamper-EVIDENT, not tamper-PROOF: an attacker with
   full database write access can rebuild a chain and head. External head
   anchoring (operator-signed manifests) is the documented next hardening.
2. Detection quality depends on operator-supplied identities and ownership;
   unusual response representations may cap at SUSPECTED by design.
3. Continuous fuzzing runs in CI only after publication (sandbox has no
   GitHub access); sessions here were 15s/target.
4. CI workflow is defined but unexecuted on GitHub infrastructure; the same
   gate was executed locally and is green.
5. AI assistance, plugins, SARIF export: intentionally not implemented
   (optional per spec §7; verdict path stays deterministic).
6. Mock-app coverage: write-path testing (creation) is unit-covered but not
   in the E2E matrix (E2E runs with write methods disabled, matching
   default safety posture).

## J. Final verdict

**READY FOR OWNER ACCEPTANCE**

All original mandatory requirements are implemented and verified; critical
workflows run end-to-end; the confirmation engine enforces every mandatory
proof condition through a single non-bypassable gate; ownership,
identity separation, false-positive protections, safety/scope enforcement,
evidence integrity, storage, reports and CLI workflows all pass their gates;
no unresolved critical or high-severity blocker exists; documentation and
version metadata are consistent; a clean extraction and rebuild from the
final source archive succeeds.

The owner's manual acceptance testing is next. Any defects found resume the
lifecycle: **CODING → CHECK → FIX → RECHECK → CONTINUE**.
