> Initial release: **v0.1.0** (owner designation, 2026-11-21). The 57 rows
> below are verified against the v0.1.0 release candidate; internal
> milestone history remains in `docs/milestones.md`.

# OWNTRACE Acceptance Matrix

Single source of truth for requirement status. Classifications:
**verified** (implemented + test-proven) · **partial** (implemented, coverage
thin) · **missing** · **defective→fixed** (found by audit, fixed with
regression test). Updated per milestone; see `docs/milestones.md` for the
defect ledger.

| # | Requirement | Location | Classification | Evidence |
|---|---|---|---|---|
| 1 | Deny-by-default scope (host/path/scheme/method) | `internal/scope` | verified | `scope_test.go`; security suite |
| 2 | Redirect-hop scope validation | `internal/httpclient` | verified | `client_test.go`; Sec-1 escape test |
| 3 | Request budgets (global/target) | `internal/scope` | verified | `TestRequestBudgets` |
| 4 | Rate limiting + bounded concurrency | `internal/safety` | verified | `safety_test.go` |
| 5 | Write-method gating + destructive-path block | `internal/safety` | verified | `safety_test.go`; Sec-2 (zero DELETEs) |
| 6 | Fail-closed safety (no scope ⇒ no requests) | `internal/safety` | verified | engine guard |
| 7 | Independent auth profiles (bearer/jwt/cookie/header/basic/none) | `internal/auth` | verified | `manager_test.go` |
| 8 | Identity separation — same identity never confirms | `internal/verification` policy | verified (v0.2.0) | `TestSecSameIdentityCannotConfirmEvenWhenConfigDisabled` |
| 9 | Credential redaction (headers/bodies/logs/URLs) | `internal/redact` | verified | `redact_test.go`; CLI/report leak tests |
| 10 | Discovery: URLs, HAR 1.2, OpenAPI 3.x, Swagger 2.0, crawl | `internal/discovery` | verified | `discovery_test.go` |
| 11 | Endpoint templating + dedup with provenance | `internal/endpoints` | verified | `endpoint_test.go` |
| 12 | Object candidate extraction | `internal/objects` | verified | `extract_test.go` |
| 13 | Ownership states confirmed/declared/inferred/unknown | `internal/ownership` | verified | `registry_test.go` |
| 14 | Inferred/unknown ownership never confirms | `internal/ownership` + policy | verified (v0.2.0) | `TestAllowedForConfirmedInvariant`; policy tests |
| 15 | Central confirmation gate (§4.3) | `internal/verification/policy.go` | verified (v0.2.0) | `TestPolicyEveryMissingPrerequisiteBlocksConfirmation` |
| 16 | Owner baseline + resource identity controls | `internal/verification` | verified | classify matrix tests; E2E |
| 17 | Negative control mandatory & fail-closed | `internal/verification` | verified (v0.2.0) | `TestSecMissingNegativeControlCannotConfirm` |
| 18 | Public-content probe mandatory & fail-closed | `internal/verification` | verified (v0.2.0) | `TestSecPublicAdminPageRejected` |
| 19 | Cache analysis mandatory; buster-ignoring cache blocked | `internal/verification` | verified (v0.2.0) | `TestSecCacheAnalysisDisabledStillBlocksConfirmation`, `TestSecCacheIgnoringBustersCannotConfirm` |
| 20 | Repeatability control | `internal/verification` | verified | policy tests; E2E |
| 21 | Evidence-required confirmation | `internal/verification` + `internal/evidence` | verified (v0.2.0) | `TestSecEvidencePersistenceFailureCannotConfirm` |
| 22 | Evidence capture redaction + truncation | `internal/redact`, `internal/httpclient` | verified | client tests |
| 23 | Evidence hash chains + head (tamper-EVIDENT) | `internal/evidence`, `internal/storage` | verified (v0.2.0) | chain tamper tests (payload/deletion/head) |
| 24 | Trusted head checkpoint for external anchoring (§35: tamper-EVIDENT, never tamper-PROOF) | `results head`, `results integrity --anchored-head`, `storage.EvidenceCheckpoint/VerifyAgainstHead` | verified (2026-11-21 audit) | internal/storage/evidence_checkpoint_test.go::TestEvidenceCheckpointAnchoring — full-chain rewrite (every hash recomputed, stored head updated) passes record verification but FAILS anchored comparison; docs/evidence-and-reporting.md documents the trust boundary |
| 25 | SQLite migrations + session lifecycle + recovery | `internal/storage` | verified | `storage_test.go` |
| 26 | Append-only evidence + retention cleanup | `internal/storage` | verified | `storage_test.go`; `results cleanup` |
| 27 | Findings state machine with reasoned transitions | `internal/finding` | verified | `finding_test.go` |
| 28 | Categories: horizontal/vertical/anonymous/cross-tenant/nested | `internal/verification`, `internal/scan` | verified | E2E matrix |
| 29 | Decoy / soft-404 / echo traps rejected | `internal/verification` | verified (v0.2.0) | `TestClassifyMatrix`; `TestSecSoft404IsInconclusive` |
| 30 | Cache-served owner response ≠ attacker access | `internal/verification` | verified (v0.2.0) | E2E cached-docs; pathcache trap |
| 31 | Controlled creation workflow (confirmed ownership) | `ownership.Mapper.runCreation` (objects.creation + safety.allow_write_methods gate) | verified (2026-11-21 audit) | internal/scan/e2e_creation_inference_test.go::TestE2EControlledCreationConfirmsOwnership (POST create → provenance objects.creation → CONFIRMED finding on created id) + TestE2ECreationWriteGateCannotBeBypassed (enabled without allow_write_methods → validation error) |
| 32 | Listing-membership inference | `ownership.Mapper.mineCollection` (objects.mine_collections) | verified (2026-11-21 audit) | internal/scan/e2e_creation_inference_test.go::TestE2EListingInferenceNeverConfirms — mined ids are authorization-tested, stay non-CONFIRMED (§21 invariant) while the same vulnerable object under declared ownership IS confirmed |
| 33 | Reports JSON/MD/HTML/CSV, verdict-segregated, no fabricated severity | `internal/report` | verified | `report_test.go` |
| 34 | CLI: 10 command families, exit codes 0/1/2/3/4/5, JSON output | `internal/cli` | verified | `cli_test.go`; E2E CLI smoke |
| 35 | Dry-run mode | `internal/scan` | verified | E2E dry-run test |
| 36 | Graceful cancellation (SIGINT/SIGTERM) | `internal/cli` + all layers | verified | Sec-5 cancellation test |
| 37 | Graceful shutdown preserving partial results | `internal/storage` | verified | interrupted-session recovery |
| 38 | Fuzz tests for parsers (HAR/OpenAPI/URL, hostile seeds) | `internal/discovery/fuzz_test.go` | verified (stale row corrected 2026-11-21) | 3 fuzz targets; seed corpora run in unit tests |
| 39 | Dependency vulnerability review (govulncheck) | go.mod (yaml.v3, modernc.org/sqlite) | verified (clean at v0.9.0; deps unchanged through v0.1.0) | CHANGELOG [1.0.0] historical gate record |
| 40 | Cross-platform binaries + checksums (release packaging) | `scripts/build-release.sh` + workflows | verified (v0.1.0 gate: 5 platform binaries, SHA256SUMS 7/7; GitHub-side dispatch is owner-owned) | release-gates/v0.1.0 |
| 41 | Reproducible build (same toolchain → same hash) | build flags | verified | identical SHA-256 for double build |
| 42 | Docs match behavior (README + 10 guides + examples) | `docs/`, `examples/` | verified (demo executed) | examples/vulnerable-demo walkthrough |

| 43 | Canonical CLI: scan -u/--target/--report/--openapi/--har/--workflow/--profile/--list/--scope/--output/--no-discover; discover --target; report --format | `internal/cli` overlay + flags | verified | e2e_flags_test.go; scan -u --dry-run E2E |
| 44 | doctor diagnostics (§41) with actionable remediation, no target contact | `internal/cli/cmd_doctor.go` | verified | doctor exit codes 0/2; real run finds db-permission WARN |
| 45 | history command (§14) | `internal/cli/cmd_history.go` | verified | history output test via CLI smoke |
| 46 | BFLA as separate finding type (function-level battery, §24/§29) | `internal/verification` policy+engine | verified | policy_battery_test; E2E admin/stats → broken_function_level_authorization |
| 47 | BOPLA with declared restricted properties + fabrication guard | `internal/verification/properties.go` | verified | engine_bopla_test.go (re-route + no-fabrication) |
| 48 | Sensitive business-flow battery (§24/§29) | `internal/verification/flow.go` | verified | E2E business-flow bypass CONFIRMED |
| 49 | Stateful workflow engine (§25): state, extraction, expects, negative control, cleanup | `internal/workflow` | verified | engine_test.go + E2E via mockapp fixture |
| 50 | GraphQL adapter (§26): HAR harvest, node/variables battery, partial-data, budgets | `internal/graphql` + `internal/verification/graphql.go` | verified | graphql tests + E2E HAR fixture → CONFIRMED |
| 51 | Finding triage: severity (no CVSS), CWE/OWASP, notes, accepted-risk, suppression (§34) | `internal/finding` + storage v3 | verified | enrichment_test + storage round-trip + migration v2→v3 |
| 52 | Storage backup/restore/export/import with fail-closed evidence verification (§35–36) | `internal/storage/storage_transfer.go` + CLI | verified | e2e_transfer_test (round trip + tampered refusal) |
| 53 | Database file 0600 regardless of umask (§36) | `internal/storage.Open` | verified | perm_test.go |
| 54 | Explicit proxy support, dial guard preserved (§30) | `internal/httpclient.SetProxy` + config.network | verified | config validation; bootstrap wiring |
| 55 | Coverage accounting: planned vs executed vs safety-skipped (§33) | `internal/scan` Summary | verified | summary output in E2E |
| 56 | --no-discover inventory reuse with stale/scope rejection (CLI §5) | `internal/scan.loadStoredInventory` | verified | e2e_flags_test (reject + reuse) |
| 57 | help command (§14) | `internal/cli/cmd_setup.go` | verified | help root + subcommand |

Legend note: rows marked *(v0.2.0)* were defective or missing in the
inherited v0.1.0 candidate and are now implemented with the regression tests
listed in the defect ledger (`docs/milestones.md`).
