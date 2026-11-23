# Installation

## Install (recommended)

One command installs OWNTRACE — no repository clone, no source navigation, no manual build:

```bash
go install -v github.com/Lutfifakee-Project/owntrace/cmd/owntrace@latest
```

`@latest` resolves to the newest published release (currently v0.1.2). To reproducibly
install an exact published version, pin it:

```bash
go install -v github.com/Lutfifakee-Project/owntrace/cmd/owntrace@v0.1.2
```

Then verify:

```bash
owntrace version
# OWNTRACE 0.1.2 (dev, linux/amd64, go1.27.4)
owntrace help
```

The version line shows the released `Version` constant from `internal/version` plus
build metadata. For `go install` builds the commit field reads `dev` (the official
release binaries carry the `release-build-<commit>` stamp instead), followed by the
host platform and the Go toolchain used. `go install` always builds for the platform
it runs on.

## Prerequisites

- **The `go` command.** OWNTRACE's `go.mod` requires the **Go 1.27.4** toolchain.
  - Go 1.21 or newer with the default `GOTOOLCHAIN=auto` downloads go1.27.4
    automatically on first use — no manual toolchain setup. Verified: Go 1.21.0 with
    default settings installs OWNTRACE v0.1.1 successfully (`go: downloading
    go1.27.4 (linux/amd64)`).
  - With `GOTOOLCHAIN=local`, or a Go release older than 1.21 (which ignores
    toolchain switching), Go **1.27.4 or newer** must already be installed. Verified
    error on Go 1.21.0 with `GOTOOLCHAIN=local`: `github.com/Lutfifakee-Project/
    owntrace@v0.1.1 requires go >= 1.27.4 (running go 1.21.0; GOTOOLCHAIN=local)`.
- **`PATH`.** The executable is installed as `owntrace` into `GOBIN` if set, otherwise
  into `GOPATH/bin` (by default `~/go/bin`). Make sure that directory is on your
  `PATH`:

  ```bash
  export PATH="$HOME/go/bin:$PATH"   # bash/zsh example; adjust for your shell
  ```

- **Internet access** for the module and toolchain downloads from the Go module
  proxy (`proxy.golang.org`). Installation needs no other network access; the
  scanner itself only ever contacts your authorized targets.
- **~50 MB disk** for the binary, module cache and session data. No database
  server, no API keys, no services, no containers.

## Upgrade

Re-running the install command upgrades in place:

```bash
go install -v github.com/Lutfifakee-Project/owntrace/cmd/owntrace@latest
```

After upgrading:

1. Stop any running `owntrace scan` process.
2. Run `owntrace doctor`. It validates the configuration schema against the new
   binary (`[PASS] upgrade: configuration schema matches this binary`) and reports
   exactly which fields need adjustment when the schema changed.
3. Sessions, findings and evidence in `owntrace-data/` are migrated in place;
   `owntrace results integrity` re-verifies the full evidence chain after an
   upgrade. Back up the directory first for belt-and-braces safety.

OWNTRACE stores all state in the project-local `owntrace-data/` directory and reads
configuration from `owntrace.yaml` / `auth.yaml` — upgrading replaces only the binary.

## Uninstall

OWNTRACE is a single self-contained binary with an embedded SQLite store — there is
no service, no container and no external database to remove:

1. Delete the **executable**: `rm "$(command -v owntrace)"`. It lives in `GOBIN` if
   set, otherwise in `GOPATH/bin` (default `~/go/bin`).
2. Delete the **project state**: `rm -rf owntrace-data/` — sessions, findings and
   evidence (file mode 0600, owner-only). This is per-project data, not a global
   cache.
3. Remove project files you no longer need: `owntrace.yaml`, `auth.yaml`
   (credentials, owner-only), `auth.secrets` (if used), and the `owntrace-data`
   entry from your `.gitignore`.

The executable (step 1) and the per-project data and configuration (steps 2–3) are
independent: removing the binary keeps your data, and removing the data keeps a
working binary. No registry entries, launch agents, or global caches are written by
OWNTRACE; removing the items above leaves the machine clean.

## Prebuilt release binaries (optional alternative)

If you prefer not to install Go, download the five platform binaries and the
`SHA256SUMS` manifest from the
[releases page](https://github.com/Lutfifakee-Project/owntrace/releases):
`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.

```bash
sha256sum -c SHA256SUMS              # all seven entries must report OK
chmod +x owntrace-0.1.2-linux-amd64  # use the file for your platform
mv owntrace-0.1.2-linux-amd64 ~/bin/owntrace   # any directory on your PATH
owntrace version
```

The release binaries are built with `CGO_ENABLED=0` and report the release build
stamp (`release-build-<commit>`) in `owntrace version`.

## Building from source

Building from source, reproducible-build verification and the bundled vulnerable
lab application are contributor workflows — see [CONTRIBUTING.md](CONTRIBUTING.md).
