# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

OWNTRACE follows semantic versioning (`vMAJOR.MINOR.PATCH`). Security fixes
are released as PATCH versions and noted in `CHANGELOG.md`.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report vulnerabilities in OWNTRACE itself (not findings against applications
you tested with it) to the maintainers via a private GitHub security advisory
at `https://github.com/Lutfifakee-Project/owntrace/security/advisories`.

Include:
- affected version (`owntrace version`),
- steps to reproduce,
- impact assessment,
- any logs (already redacted — if the report itself would contain a live
  credential, do not include it).

You will receive an acknowledgment within 7 days. We aim to release fixes for
critical issues within 30 days.

## Scope

In scope:
- Credential leakage through logs, reports, evidence or the database.
- Scope-enforcement bypasses (requests leaving the configured targets).
- Injection into reports or evidence via target-controlled content.
- Unsafe handling of malformed HAR/OpenAPI input.
- Evidence integrity failures (hashes that verify tampered data).

Out of scope:
- Vulnerabilities in applications you test **with** OWNTRACE.
- Issues requiring physical access or a compromised host.
- Social engineering.

## Security design invariants

OWNTRACE enforces the following in code — contributions that weaken them will
be rejected:

1. **Deny-by-default scope.** No request leaves the configured targets; every
   redirect hop is re-validated; subdomains are not auto-authorized.
2. **Write-method gating.** POST/PUT/PATCH/DELETE require explicit
   `safety.allow_write_methods: true`; destructive path patterns are blocked
   regardless of method policy.
3. **Credential hygiene.** Secrets live only in `auth.yaml` (0600) or
   environment variables; everything persisted or exported passes the
   redaction layer; `owntrace config show` is always redacted.
4. **Evidence immutability.** Evidence rows are append-only and SHA-256
   hashed; `owntrace results integrity` detects tampering.
5. **Verdict discipline.** CONFIRMED requires owner baseline, verified
   identity separation, evidence-backed ownership, reproducible cross-account
   access with object data present, and no cache/decoy artifact.
