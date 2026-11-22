# Architecture

## Module map

```
cmd/
  owntrace/          CLI entrypoint (thin; all logic in internal/cli)
  mockapp/           Deliberately vulnerable lab application (test fixture)

internal/
  cli/               Command framework + all command implementations
  config/            YAML loading, validation, defaults, env secret refs
  scope/             Deny-by-default scope checker (hosts/paths/methods/budgets)
  safety/            Rate limiting, budgets, method guards, concurrency slots
  httpclient/        Controlled client: redirect validation, bounded reads
  auth/              Profile manager + identity separation verification
  discovery/         Orchestrator + URL/HAR/OpenAPI/Swagger/crawl parsers
  endpoints/         Endpoint model, templating, deduplication
  objects/           Candidate extraction (endpoints, responses)
  ownership/         Registry (confirmed/declared/inferred/unknown) + mapping
  verification/      The evidence-based testing engine + decision matrix
  evidence/          Append-only, SHA-256 integrity-protected records
  finding/           Finding model + state machine
  report/            JSON / Markdown / HTML / CSV generators
  storage/           SQLite: migrations, sessions, findings, evidence, audit
  redact/            Credential & PII redaction (single choke point)
  logger/            Leveled, redaction-aware logging
  util/              JSON path walking, helpers
  version/           Version string (ldflags-stamped commit)
  benchmarks/        Performance benchmarks for critical components
```

## Data flow (scan)

```
config + auth.yaml
      │
      ▼
scope.Checker ─── safety.Engine ─── httpclient.Client     (every request)
      │                │                  │
      ▼                ▼                  ▼
discovery.Run ──► endpoints.Set + ResponseSamples
      │
      ├─► auth.Manager.VerifySeparation   (abort gate)
      │
      ├─► ownership.Mapper ──► Registry ──► storage.objects
      │        (declared → creation → collections → HAR inference)
      ▼
scan.buildItems ──► TestItems ──► verification.Engine (bounded workers)
                                      │
                                      ├─► evidence.Capture (every exchange)
                                      ├─► finding.Transition (reasoned)
                                      └─► storage.findings
                                              │
                                              ▼
                                    report generators ──► reports/
```

## Design decisions

**Interfaces at meaningful seams.** `storage` behind a `Store` contract for
evidence, `scope.Checker` consumed through a narrow adapter in the mapper —
enough for testing without speculative abstraction.

**Enforcement in code, not prose.** Scope, budgets, method guards, redaction
and verdict gates are library-level: a forgotten config flag cannot weaken
them, and the safety engine fail-closes (no scope ⇒ no requests).

**Deterministic verdicts.** The decision matrix is pure logic over captured
exchanges (`classify`) — unit-testable without network, then exercised
end-to-end against the mock application.

**Redaction at the boundary.** The HTTP client and evidence engine redact
when data enters the system; no later component can leak what was never
stored in the clear.

**SQLite as the only persistence.** One file, WAL mode, single-writer
serialization, versioned migrations. Sessions recover as `interrupted` after
an unclean shutdown; evidence is append-only.

**No AI in the verdict path.** Detection is deterministic and inspectable.
(Assistance features may explain findings, but nothing can promote a verdict.)

## Concurrency model

- Worker pool bounded by `limits.concurrency`; items flow through a channel.
- The safety engine's semaphore is the hard cap on concurrent requests;
  rate limiting books the earliest send time per host under a mutex, then
  waits outside it (no lock held while sleeping).
- SQLite access is serialized through a mutex and a single connection —
  correct and fast enough for scan-scale writes.
- Context cancellation reaches every layer; workers drain and exit.

## Testing strategy

| Layer | Tests |
|---|---|
| Unit | scope, safety, endpoints, objects, redaction, analysis heuristics, config |
| Integration | full pipeline vs. `internal/mockapp` (vulnerable + protected matrix) |
| Security | scope escapes, destructive refusals, malformed inputs, cancellation |
| Race | `go test -race ./...` — clean |
| Benchmarks | redaction, similarity, hashing, scope checks |
