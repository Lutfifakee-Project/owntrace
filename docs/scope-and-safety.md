# Scope and Safety Guide

## The authorization boundary

OWNTRACE is a testing tool: it sends requests that a real client could send,
but it does so **only where you are authorized to test**. The scope section of
`owntrace.yaml` is the single source of truth, and it is **deny-by-default**:

1. Only hosts explicitly listed in `scope.targets` are contacted.
2. Subdomains are NOT auto-authorized (`allow_subdomains: false` default).
3. Only schemes listed per target (`schemes`) are used.
4. Only paths matching `include_paths` and not matching `exclude_paths`.
5. Only methods in the target's `allowed_methods` (or the global list).
6. Paths matching any `blocked_path_patterns` regex are refused regardless of
   method — the default list covers logout, delete, destroy, remove,
   password, payment, checkout, purchase, billing, unsubscribe, cancel,
   revoke, reset, transfer, refund, payout, close, disable, deactivate.
7. Per-target (`max_requests`) and global (`max_requests_total`) request
   budgets; exceeding either stops requests with a clear budget error.

`owntrace scope check --url ... --method GET` verifies any URL against the
configured scope without sending a request (exit code 3 when denied).

## Redirect discipline

The HTTP client never follows redirects blindly. Each hop is resolved to an
absolute URL and re-validated against the scope **before** being requested:

- in-scope hops are followed and recorded in the evidence,
- out-of-scope hops are blocked; the exchange carries `scope_blocked: true`
  and the hop record with the denial reason.

This closes the classic scope-escape: an in-scope endpoint redirecting to an
attacker-controlled host is *not* contacted. Redirects to login pages are
treated as denials during verification, not as object access.

## Request controls

| Control | Default | Meaning |
|---|---|---|
| `rate_per_second` | 5 | Global ceiling, also enforced per host |
| `concurrency` | 4 | Bounded worker pool; no unbounded goroutines |
| `request_timeout_seconds` | 15 | Per-request timeout |
| `max_response_bytes` | 2 MiB | Bodies are read up to the cap and flagged truncated |
| `max_redirects` | 5 | Hop limit per logical request |
| `retries` | 1 | Transport-error retries only; never on HTTP errors |

Fail-safe: if a safety engine is constructed without a scope checker, it
refuses every request rather than allowing unscoped traffic.

## Destructive operations

`GET`, `HEAD` and `OPTIONS` are safe by default. `POST`, `PUT`, `PATCH`,
`DELETE` are refused unless:

1. `safety.allow_write_methods: true` (explicit, global opt-in), **and**
2. the URL does not match any blocked pattern, **and**
3. the target's method allowlist includes the method.

The intended write-operation workflow is narrow: enable writes only to run a
controlled **creation workflow** (`objects.creation`) that creates disposable
test objects, with `verification.repeats` kept low and the target being a
test/staging environment you own.

OWNTRACE never attempts to bypass authentication, access controls, WAFs or
rate limits; it sends ordinary, rate-limited requests and accepts what the
application answers.

## Cancellation and shutdown

SIGINT / SIGTERM cancel the run context. In-flight requests abort, worker
pools drain, the session is finalized (`interrupted`), and everything already
verified remains queryable and reportable. Restarting later, `owntrace
verify` can re-run the controls that were skipped.

## Dry-run

`owntrace scan --dry-run` runs discovery and ownership mapping and prints the
exact test plan (object, URL, owner, ownership state) without sending any
verification request. Use it before every first run against a new target.
