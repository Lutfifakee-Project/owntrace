# Contributing to OWNTRACE

Thank you for improving OWNTRACE. This project has one hard rule:

> **Every finding must be supported by authorization evidence, not merely
> response differences.** Contributions that weaken verdict discipline —
> e.g. promoting findings on status codes or similarity alone, relaxing the
> scope engine, or loosening credential redaction — will be rejected.

## Development setup

```bash
git clone https://github.com/Lutfifakee-Project/owntrace.git
cd owntrace
go build ./...
go test ./...
go test -race ./...
go vet ./...
gofmt -l .   # must be empty
```

Go ≥ 1.22. No external services are needed; all tests run against an
in-process mock application (`internal/mockapp`).

## Workflow: CODING → CHECK → FIX → RECHECK

1. Pick or open an issue; state the expected behavior.
2. Implement with tests (unit for logic, integration in `internal/scan` for
   pipeline behavior).
3. Run the full gate: `gofmt`, `go vet ./...`, `go test -race ./...`.
4. **Every fixed defect gets a regression test** that fails without the fix.
5. Never fix a false positive by suppressing a specific endpoint or response
   pattern — fix the underlying detection logic, then prove it in the matrix.

## Code standards

- Match the existing style; keep functions small and single-purpose.
- Document exported identifiers; explain *why* in comments where behavior is
  policy-driven (scope, verdicts, redaction).
- No new dependencies without justification; the core scanner must remain
  deterministic, inspectable and offline-capable.
- Concurrency: bounded goroutines only; every context must be respected.

## Security-sensitive areas

Changes to these packages require extra scrutiny and tests:
`internal/scope`, `internal/safety`, `internal/redact`, `internal/evidence`,
`internal/verification`. See `SECURITY.md` for the invariants.

## Commit messages

Use imperative mood, reference the issue, and note behavior changes:

```
verification: add public-content probe to filter decoy endpoints

Fixes #12. Echo-style endpoints that return identical generic content
to owner and attacker were reaching CONFIRMED via the anonymous
category; the probe rejects horizontal findings when the object data
is equally available without credentials.
```

## Reporting defects found while using the tool

Open an issue with: command line used (redact tokens!), config snippet
(`config show` output), relevant finding ID and evidence hashes, expected vs
actual verdict. Never paste live credentials.
