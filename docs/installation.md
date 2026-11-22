# Installation

## Requirements

- Go ≥ 1.22 (only for building from source)
- ~50 MB disk for the binary, module cache and session data
- No database server, no API keys, no network access beyond your authorized
  targets — the scanner is fully local.

## Build from source

```bash
git clone https://github.com/Lutfifakee-Project/owntrace.git
cd owntrace
go build -trimpath \
  -ldflags "-s -w -X github.com/Lutfifakee-Project/owntrace/internal/version.Commit=$(git rev-parse --short HEAD)" \
  -o owntrace ./cmd/owntrace
./owntrace version
# OWNTRACE 0.1.0 (<commit>, linux/amd64, go1.27.4)
```

`-trimpath` removes local paths from the binary; the `-ldflags` stamp records
the commit so `owntrace version` is meaningful.

## Reproducible builds

With the same Go toolchain version, `go build -trimpath` is deterministic:
the binary checksum depends only on the source tree contents and the stamped
commit. Verify:

```bash
go build -trimpath -o a ./cmd/owntrace
go build -trimpath -o b ./cmd/owntrace
sha256sum a b   # identical
```

The module dependencies are pinned in `go.mod`; `go.sum` contains their
hashes. CI (`.github/workflows/ci.yml`) builds with the pinned toolchain.

## The lab application

A deliberately vulnerable demo application ships with the repository for
learning and for validating a build:

```bash
go run ./cmd/mockapp --addr 127.0.0.1:8099
```

It binds to loopback, holds three users (`alice`, `bob`, `admin`) and fixed
test data. It is a **test fixture** — never expose it to a network you do not
control.

## Verify the installation

```bash
owntrace version
owntrace help
go test ./...        # from a source checkout: full test suite
```

## Upgrade

OWNTRACE stores all state in the project-local `owntrace-data/` directory and
reads configuration from `owntrace.yaml` / `auth.yaml`. Upgrading is a binary
replacement:

1. Stop any running `owntrace scan` process.
2. Replace the binary with the new release build (or `go install
   github.com/Lutfifakee-Project/owntrace/cmd/owntrace@vX.Y.Z`).
3. Run `owntrace doctor`. It validates the configuration schema against the
   new binary (`[PASS] upgrade: configuration schema matches this binary`) and
   reports exactly which fields need adjustment when the schema changed.
4. Sessions, findings and evidence in `owntrace-data/` are migrated in place;
   `owntrace results integrity` re-verifies the full evidence chain after an
   upgrade. Back up the directory first for belt-and-braces safety.

## Uninstall

OWNTRACE is a single static binary with an embedded SQLite store — there is
no service, no container and no external database to remove:

1. Delete the binary (`rm "$(command -v owntrace)"` or remove the file you
   downloaded/built).
2. Delete the project state directory `rm -rf owntrace-data/` (contains
   sessions, findings and evidence; file mode 0600, owner-only).
3. Remove project files you no longer need: `owntrace.yaml`, `auth.yaml`
   (credentials, owner-only), `auth.secrets` (if used), and the `owntrace-data`
   entry from your `.gitignore`.

No registry entries, launch agents, or global caches are written by OWNTRACE;
removing the three items above leaves the machine clean.
