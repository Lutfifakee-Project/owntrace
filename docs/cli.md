# CLI Reference

Global flags (valid on every command, placed **after** the subcommand):

| Flag | Default | Description |
|---|---|---|
| `--config` | `./owntrace.yaml` | Main configuration file |
| `--auth` | `./auth.yaml` | Credentials file (chmod 600) |
| `--log-level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `--quiet` | off | Suppress log output (machine-readable runs) |
| `--help`, `-h` | — | Command help with examples |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Usage error (unknown command, missing required flag) |
| 2 | Configuration error (invalid YAML, missing profile, bad permissions) |
| 3 | Scope violation (e.g. `scope check` on an out-of-scope URL) |
| 4 | Runtime error (network failure after retries, storage failure, cancelled) |
| 5 | Scan completed **with CONFIRMED findings** (CI-friendly) |

## Commands

### `owntrace version`
Prints version, commit, platform and Go version.

### `owntrace init`
Scaffolds `owntrace.yaml`, `auth.yaml` (0600) and a `.gitignore` entry.
Never overwrites existing files unless `--force` is given.

### `owntrace config validate`
Loads and validates both files; prints a one-line summary.

### `owntrace config show [--json]`
Prints the effective configuration with **all secrets redacted**. There is no
flag to show secrets — pipe them from `auth.yaml` yourself if you truly need
to (you almost never do).

### `owntrace scope validate`
Compiles the scope section (invalid regexes fail here, before any request)
and prints the target list plus the safety posture.

### `owntrace scope check --url URL [--method GET]`
Checks a single URL/method against the scope without sending anything.
Exit code 3 when denied; the reason is always printed.

### `owntrace auth add --name NAME --type TYPE [flags]`
Adds or replaces a profile in `auth.yaml` (0600 preserved).

| Flag | Meaning |
|---|---|
| `--name` | Profile name (required) |
| `--type` | `bearer` \| `jwt` \| `cookie` \| `header` \| `basic` \| `none` |
| `--token` | Token value; `{{ env VAR }}` supported |
| `--username` / `--password` | For `basic` |
| `--role` | Optional label, e.g. `admin` (drives vertical testing) |
| `--identity-endpoint`, `--identity-field` | Identity probe configuration |

### `owntrace auth list`
Table of profiles: name, type, role, whether credentials are set (never the
values), identity probe.

### `owntrace auth check [--json]`
Runs identity probes for all profiles and verifies pairwise distinctness.
Fails (exit ≠ 0) when `require_distinct_identities` is set and separation
cannot be verified.

### `owntrace discover urls|har|openapi|crawl`
Runs one discovery source and prints the in-scope endpoint inventory.
Nothing is tested; no findings are produced.

| Subcommand | Flags |
|---|---|
| `urls` | `--url URL` (repeatable) |
| `har` | `--file PATH` (repeatable) |
| `openapi` | `--file PATH` (repeatable) |
| `crawl` | `--seed URL` (repeatable) |

### `owntrace scan [--dry-run] [--json]`
The full pipeline. Prints a testing summary (scope, safety posture, profiles)
before starting. `--dry-run` performs discovery and ownership mapping only —
no verification requests are sent.

Exit codes: 0 clean · 5 confirmed findings · others as per the table above.

### `owntrace verify [--finding ID] [--state SUSPECTED]`
Re-runs the verification battery for one finding or all findings in a state,
appending new transitions to the history.

### `owntrace report [--session ID] [--formats json,markdown,html,csv] [--out DIR]`
Regenerates reports for a session (default: latest). Reports are also
auto-generated after every `scan`.

### `owntrace results list [--session ID] [--state STATE] [--json]`
Lists findings of a session with state, category, title, endpoint, ID.

### `owntrace results show --finding ID`
Full finding detail plus evidence records with per-record integrity status.

### `owntrace results sessions`
Lists scan sessions with status (`running` / `completed` / `interrupted`).

### `owntrace results integrity`
Re-hashes **all** stored evidence; fails if any record was tampered with.

### `owntrace results cleanup`
Deletes sessions older than `retention.days` including their findings,
objects, evidence and audit rows.
