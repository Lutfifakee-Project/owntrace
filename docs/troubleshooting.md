# Troubleshooting

## Configuration errors (exit code 2)

**`config version N not supported`** — the file says `version: N`; set
`version: 1`.

**`auth file has overly broad permissions`** — `chmod 600 auth.yaml`.

**`profile "x" is not defined in auth`** — objects reference a profile that
does not exist in `auth.yaml`. List profiles: `owntrace auth list`.

**`objects.creation.enabled requires safety.allow_write_methods=true`** —
creation workflows are write operations; enable writes explicitly or disable
the workflow.

**`scope.targets must list at least one explicitly authorized host`** —
add a target. Hosts have no scheme (`host: "api.example.com"`, ports with
`host: "127.0.0.1:8080"`).

## Scope denials (exit code 3)

**`host "x" is not in the configured scope`** — add the host to
`scope.targets`. Subdomains need the exact host or `allow_subdomains: true`.

**`path ... outside include patterns`** — widen `include_paths` (prefix
match: `/api` covers `/api` and everything below it).

**`method POST not permitted`** — add it to the target's
`allowed_methods` and the global list. Writes additionally need
`safety.allow_write_methods: true`.

**`path ... matches blocked (destructive) pattern`** — the default denylist
blocks logout/delete/payment-like paths even for reads; adjust
`blocked_path_patterns` deliberately if the path is safe.

## Authentication problems

**`identity separation is required ... could not be verified`** —
`owntrace auth check` shows per-profile detail. Common causes: relative
identity endpoint (must be absolute), wrong `field` path, expired token,
404 probe. If the two profiles genuinely share an identity, fix the tokens —
comparing a user with themselves is meaningless.

**`profile "userA": bearer token is empty`** — the env reference resolved to
nothing; the variable is unset in this shell.

## Verification verdicts

**Many `INCONCLUSIVE` findings** — owner baselines failing. Check: identifier
correct? endpoint returns object data (not a wrapper page)? profile token
valid? Run `owntrace results show --finding F-…` and read the baseline
evidence.

**`SUSPECTED` with `cache_analysis=FAIL`** — a shared cache served the
owner's response; the cache-busted retry denied. Confirm manually with a
cache-busting replay before reporting.

**`REJECTED` for something you believe is vulnerable** — the decision matrix
needs evidence: the object identifier must appear in the owner baseline, and
the non-owner response must carry the object's data fields. If the endpoint
returns the object in an unusual representation (binary, deeply nested,
renamed fields), the heuristics may cap at SUSPECTED — that is intentional.
Report the case with the finding ID; heuristics improve via regression tests,
not per-endpoint suppressions.

**`ERROR` findings** — transport failures after retries: timeouts
(`limits.request_timeout_seconds`), connection resets, or the target
rate-limiting you. Lower `rate_per_second` if the application pushes back.

## Storage and sessions

**Session stuck `running`** — the process died without cleanup; the next
start marks it `interrupted` automatically.

**Database locked / busy errors** — another process holds the SQLite file.
OWNTRACE serializes its own writes; external readers should copy the file
first.

**Evidence integrity failures** — someone or something modified rows outside
OWNTRACE. Restore from a trusted backup; do not ignore the mismatch.

## Data management

**Disk usage grows** — evidence is capped per record (64 KiB bodies), but
long campaigns add up: `owntrace results cleanup` removes sessions older
than `retention.days`.

**Where is my data?** `<output_dir>/owntrace.db` (SQLite), reports under
`<output_dir>/reports/`, session log file if configured. Everything stays
local; nothing is sent anywhere except your authorized targets.
