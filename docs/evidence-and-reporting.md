# Evidence and Reporting Guide

## Evidence model

Every verification step captures an **evidence record**: a JSON document with
the redacted HTTP exchange (method, URL, headers, body excerpt, status,
response headers, redirect chain), the verification step metadata, and a
creation timestamp.

- **Redaction at capture.** Credential headers become `‹redacted:hash8›`
  markers; JWTs, bearer strings, long hex/base64 secrets and e-mail addresses
  are scrubbed from bodies. Bodies are truncated at 64 KiB. Response sizes
  over the configured cap are flagged.
- **Integrity.** Each record is serialized canonically (sorted keys,
  deterministic encoding) and hashed with SHA-256. `owntrace results
  integrity` re-hashes everything in the database: any modification of stored
  evidence — accidental or malicious — is detected.
- **Append-only.** There is no update or delete path for evidence; sessions
  are cleaned only through the explicit retention command.

## Finding anatomy

```json
{
  "id": "F-1A2B3C4D",
  "category": "horizontal_object_access",
  "state": "CONFIRMED",
  "title": "Horizontal cross-account access to order 'o-1001' owned by userA",
  "method": "GET",
  "url": "http://127.0.0.1:8080/api/v1/orders/o-1001",
  "resource": "order",
  "owner_profile": "userA",
  "owner_state": "declared",
  "requester": "userB",
  "confidence": 0.9,
  "reason": "non-owner response contains the target object's data
             (identifier present, similarity 1.00, owner-data field overlap
             1.00 of 4 fields)",
  "controls": [
    {"name": "identity_separation", "status": "PASS"},
    {"name": "owner_baseline",      "status": "PASS", "http_status": 200},
    {"name": "resource_identity",   "status": "PASS"},
    {"name": "negative_control",    "status": "PASS", "http_status": 404},
    {"name": "non_owner_access",    "status": "PASS", "http_status": 200},
    {"name": "cache_analysis",      "status": "PASS"},
    {"name": "repeatability",       "status": "PASS"},
    {"name": "public_content_probe","status": "PASS"}
  ],
  "transitions": [
    {"from": "DISCOVERED", "to": "CANDIDATE", "reason": "candidate object identified from declared ownership record"},
    {"from": "CANDIDATE",  "to": "TESTING",   "reason": "starting verification controls"},
    {"from": "TESTING",    "to": "CONFIRMED", "reason": "…", "evidence_id": "EV-20261117-0007"}
  ],
  "evidence_ids": ["EV-20261117-0004", "…"],
  "reproduction": [
    "# as profile 'userA'",
    "curl -sS -X GET 'http://…' -H 'Authorization: Bearer ‹redacted:1a2b3c4d›'",
    "# as profile 'userB'",
    "curl -sS -X GET 'http://…' -H 'Authorization: Bearer ‹redacted:5e6f7a8b›'"
  ],
  "remediation": "Enforce object-level authorization on every request that
                  addresses a resource by identifier…"
}
```

`reproduction` commands contain redacted credentials — substitute your own
test tokens when replaying.

## Verdicts

| State | Meaning | Action |
|---|---|---|
| `CONFIRMED` | Reproduced unauthorized access with full evidence | Verify manually with the reproduction steps, then report |
| `SUSPECTED` | Access or leak indications, one condition unmet | Human review; check the failing control |
| `INCONCLUSIVE` | Baseline broken (config issue, expired token) | Fix configuration, re-run `owntrace verify` |
| `REJECTED` | Control verified as working | Keep for regression tracking |
| `ERROR` | Transport/infrastructure failure after retries | Check connectivity/timeouts |

## Report formats

Generated automatically after each scan into `<output_dir>/reports/`:

| Format | File | Purpose |
|---|---|---|
| JSON | `report.json` | Machine processing, CI gates |
| Markdown | `report.md` | Review, tickets, advisories |
| HTML | `report.html` | Self-contained responsive page for humans |
| CSV | `findings.csv` | Spreadsheet triage |

All formats separate CONFIRMED / SUSPECTED / INCONCLUSIVE / REJECTED / ERROR
and include: executive summary, scope table, methodology, ownership registry,
per-finding details (controls, reproduction, evidence references,
remediation), and a limitations section.

## What the reports deliberately do not do

- **No CVSS, no severity, no business impact.** Severity depends on context
  only a human can judge; fabricating scores would be dishonest.
- **No confidence theater.** `SUSPECTED` findings say exactly which control
  failed and why confirmation was withheld.
- **No raw credentials.** Everything is redacted; evidence hashes prove the
  records have not been edited after the fact.

## Recommended review workflow

1. `owntrace results list` — triage by state.
2. For each CONFIRMED finding: `owntrace results show --finding F-…`,
   check controls, replay reproduction steps manually with your tokens.
3. Check the finding URL is really within your authorized scope.
4. Only then draft the disclosure — `report.md` is structured to be pasted
   into a bug bounty report with your own severity assessment.

## Trusted head checkpoint (§35) — tamper-EVIDENT, not tamper-PROOF

Each session's evidence records form a SHA-256 hash chain whose head is
stored with the session. This makes local evidence **tamper-evident**: any
single-record modification, deletion, or insertion breaks verification.

A hash chain whose head lives only in the same database is **not tamper-
proof** against an attacker who can rewrite every record and recompute every
hash. OWNTRACE therefore exposes an explicit trusted-head checkpoint:

    owntrace results head [--session ID]
    # OWNTRACE-EVIDENCE-HEAD session=S-… head=<sha256> records=N

Anchor that checkpoint line in external trusted storage (ticket, signed
log, notary). Later:

    owntrace results integrity [--anchored-head <sha> --session S-…]

re-verifies every record AND compares the current head against the anchored
one — a full-chain rewrite (every payload replaced, every hash recomputed,
the stored head updated) passes record verification but FAILS the anchored
comparison. This is regression-tested by
`internal/storage/evidence_checkpoint_test.go::TestEvidenceCheckpointAnchoring`.
Evidence is tamper-evident, never advertised as tamper-proof.
