#!/usr/bin/env bash
# Build OWNTRACE release-gate artifacts for one version.
# Usage: build-release.sh <version> <output-dir>
# Produces: five platform binaries, source tar.gz + zip, SHA256SUMS.
# Reproducible: -trimpath, fixed ldflags, deterministic archive ordering.
# -buildvcs=false: builds must not claim any git commit (vcs.revision would
# otherwise be stamped from whatever enclosing repo the tree sits in).
#
# SOURCE ARCHIVE HYGIENE (v2, post-contamination fix):
#   * The source tree is NEVER packed directly from disk. It is copied into a
#     fresh temp staging dir through an explicit denylist, guarded, verified,
#     and only then archived. Generated artifacts (release gates, download
#     dirs, previous archives, platform binaries, databases, logs, toolchains,
#     runtime data) can therefore never re-enter a source archive.
#   * Archives are written to the OUTPUT dir, which must live OUTSIDE the
#     staging tree; an existing archive is never updated, always replaced.
#   * The packager self-verifies every archive it produces (integrity,
#     zip/tar inventory equality, forbidden-entry scan, nested-archive scan,
#     mandatory-source presence, plausible size) and deletes its output on
#     any failure, so a bad archive can never ship silently.
# Env overrides (used by scripts/test-build-release.sh):
#   SRC=...        source tree to package (default: the repo root)
#   SKIP_BINARIES=1  build only the source archives (regression tests)
set -euo pipefail

VERSION="${1:?version required}"
OUT="${2:?output dir required}"
COMMIT="${COMMIT:-local-milestone}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${SRC:-$REPO_ROOT}"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/owntrace-release.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

fail() {
    echo "PACKAGER REFUSED: $*" >&2
    # Hygiene promise: never leave a half-verified archive behind.
    [ -n "${ZF:-}" ] && rm -f "$ZF" "${TF:-}" 2>/dev/null || true
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Clean staging: copy ONLY legitimate source through the denylist.
# Anchored patterns (leading /) apply at the staging root only; bare
# patterns apply at any depth (generated junk must never survive nesting).
# ---------------------------------------------------------------------------
echo "== staging clean source from $SRC =="
# The OUTPUT dir must live OUTSIDE the source tree and the staging dir, so an
# archive can never contain itself, a previous gate, or the tree it packs.
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd -P)"
case "$OUT/" in
    "$SRC"/*|"$STAGE"/*) fail "output dir ($OUT) must live outside the source/staging tree" ;;
esac
case "$SRC/" in
    "$OUT"/*) fail "source tree ($SRC) lives inside the output dir ($OUT) — refusing" ;;
esac
rsync -a \
    --exclude '/download/' \
    --exclude '/release-gates/' \
    --exclude '/audit-archive/' \
    --exclude '/dist/' \
    --exclude '/owntrace-data/' \
    --exclude '/sec-data/' \
    --exclude '/.toolchain/' \
    --exclude '/.git/' \
    --exclude '/tmp/' \
    --exclude '/tmp*' \
    --exclude '/owntrace' \
    --exclude '/owntrace.exe' \
    --exclude 'download/' \
    --exclude 'release-gates/' \
    --exclude 'audit-archive/' \
    --exclude 'owntrace-data/' \
    --exclude 'sec-data/' \
    --exclude '.toolchain/' \
    --exclude '.git/' \
    --exclude '*.db' \
    --exclude '*.db-shm' \
    --exclude '*.db-wal' \
    --exclude '*.zip' \
    --exclude '*.tar.gz' \
    --exclude '*.tgz' \
    --exclude '*.log' \
    --exclude '*.tmp' \
    --exclude '*.swp' \
    --exclude '.DS_Store' \
    --exclude 'coverage.out' \
    --exclude 'coverage.html' \
    "$SRC/" "$STAGE/owntrace/"

# ---------------------------------------------------------------------------
# 2. Guards on the staged tree (fail fast, never pack on doubt).
# ---------------------------------------------------------------------------
echo "== guarding staged tree =="
forbidden="$(find "$STAGE/owntrace" \
    \( -path '*/download/*' -o -path '*/release-gates/*' -o -path '*/audit-archive/*' \
       -o -path '*/dist/*' -o -path '*/owntrace-data/*' -o -path '*/sec-data/*' \
       -o -path '*/.toolchain/*' -o -path '*/.git/*' \
       -o -name '*.zip' -o -name '*.tar.gz' -o -name '*.tgz' \
       -o -name '*.db' -o -name '*.db-shm' -o -name '*.db-wal' \
       -o -name '*.log' -o -name '*.tmp' -o -name '*.swp' \
       -o -name 'FINAL-REPORT*.md' -o -name 'RELEASE-NOTES*.md' \
       -o -name 'acceptance-matrix.md' -o -name 'milestones.md' \) -print -quit)"
[ -z "$forbidden" ] || fail "forbidden generated artifact staged: $forbidden"

big="$(find "$STAGE/owntrace" -type f -size +10M -print -quit)"
[ -z "$big" ] || fail "staged file larger than any legitimate source file: $big"
total_kb="$(du -sk "$STAGE/owntrace" | cut -f1)"
[ "$total_kb" -lt 51200 ] || fail "staged tree too large for a source tree (${total_kb} KiB)"

for m in go.mod go.sum README.md LICENSE CHANGELOG.md SECURITY.md \
         .github/workflows/ci.yml .github/workflows/release-build.yml \
         cmd/owntrace/main.go internal/version/version.go \
         scripts/build-release.sh docs/installation.md; do
    [ -e "$STAGE/owntrace/$m" ] || fail "mandatory source file missing: $m"
done
[ -d "$STAGE/owntrace/internal" ] || fail "mandatory dir missing: internal/"
[ -d "$STAGE/owntrace/docs" ] || fail "mandatory dir missing: docs/"
[ -d "$STAGE/owntrace/examples" ] || fail "mandatory dir missing: examples/"
src_go_count="$(find "$STAGE/owntrace" -name '*.go' -not -name '*_test.go' | wc -l)"
test_go_count="$(find "$STAGE/owntrace" -name '*_test.go' | wc -l)"
[ "$src_go_count" -ge 50 ] || fail "implausibly few Go source files (${src_go_count})"
[ "$test_go_count" -ge 20 ] || fail "implausibly few Go test files (${test_go_count})"
echo "  staged: ${src_go_count} source .go, ${test_go_count} test .go, ${total_kb} KiB"

# ---------------------------------------------------------------------------
# 3. Platform binaries (built from the ORIGINAL tree, not the staging copy).
# ---------------------------------------------------------------------------
if [ "${SKIP_BINARIES:-0}" != "1" ]; then
    mkdir -p "$OUT"
    LDFLAGS="-s -w -X github.com/Lutfifakee-Project/owntrace/internal/version.Commit=${COMMIT}"
    echo "== building binaries (${VERSION}) =="
    for target in \
        linux/amd64 linux/arm64 \
        darwin/amd64 darwin/arm64 \
        windows/amd64; do
        GOOS="${target%/*}"
        GOARCH="${target#*/}"
        ext=""
        [ "$GOOS" = "windows" ] && ext=".exe"
        name="owntrace-${VERSION}-${GOOS}-${GOARCH}${ext}"
        (cd "$SRC" && GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
            go build -trimpath -buildvcs=false -ldflags "${LDFLAGS}" -o "$OUT/$name" ./cmd/owntrace)
        echo "  built $name"
    done
else
    mkdir -p "$OUT"
    echo "== binaries skipped (SKIP_BINARIES=1) =="
fi

# ---------------------------------------------------------------------------
# 4. Cut BOTH source archives from scratch into the OUTPUT dir (never update
# an existing archive; staging lives outside the output tree so an archive
# can never contain itself or a previous gate).
# ---------------------------------------------------------------------------
echo "== source archives =="
rm -f "$OUT/owntrace-${VERSION}-source.tar.gz" "$OUT/owntrace-${VERSION}-source.zip"
tar -C "$STAGE" \
    --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime='2026-01-01 00:00:00 UTC' \
    -czf "$OUT/owntrace-${VERSION}-source.tar.gz" owntrace
(cd "$STAGE" && find owntrace -type f | LC_ALL=C sort \
    | zip -q -X -@ "$OUT/owntrace-${VERSION}-source.zip")

# ---------------------------------------------------------------------------
# 5. Self-verification of the produced archives (delete output on failure).
# ---------------------------------------------------------------------------
echo "== self-verifying archives =="
ZF="$OUT/owntrace-${VERSION}-source.zip"
TF="$OUT/owntrace-${VERSION}-source.tar.gz"

unzip -tqq "$ZF" >/dev/null || fail "zip integrity check failed"
gzip -t "$TF" || fail "tar.gz integrity check failed"

# Capture BOTH listings ONCE into variables. Every self-check below greps the
# captured text — never `unzip | grep -q`: with `set -o pipefail`, grep -q
# exits early on a match, unzip dies of SIGPIPE, and a CORRECT archive would
# be misjudged as failing (observed as "missing mandatory file: LICENSE").
ZIP_LIST="$(unzip -Z1 "$ZF" || true)"
TAR_LIST="$(tar -tzf "$TF" || true)"

diff <(printf '%s\n' "$ZIP_LIST" | LC_ALL=C sort) \
     <(printf '%s\n' "$TAR_LIST" | grep -v '/$' | LC_ALL=C sort) >/dev/null \
    || fail "zip and tar logical inventories differ"

bad_entries="$(printf '%s\n' "$ZIP_LIST" | grep -E \
    '(^|/)(download|release-gates|audit-archive|dist|owntrace-data|sec-data|\.toolchain|\.git|tmp)(/|$)|\.(zip|tar\.gz|tgz|db|db-shm|db-wal|log|tmp|swp)$|FINAL-REPORT|RELEASE-NOTES|acceptance-matrix\.md|(^|/)milestones\.md' || true)"
[ -z "$bad_entries" ] || fail "forbidden entries in archive: $bad_entries"

self_entry="$(printf '%s\n' "$ZIP_LIST" | grep -F "owntrace-${VERSION}-source" || true)"
[ -z "$self_entry" ] || fail "archive contains a release archive: $self_entry"

for m in go.mod go.sum README.md LICENSE CHANGELOG.md .gitignore SECURITY.md \
         .github/workflows/ci.yml .github/workflows/release-build.yml \
         cmd/owntrace/main.go internal/version/version.go \
         scripts/build-release.sh docs/installation.md; do
    grep -qx "owntrace/$m" <<<"$ZIP_LIST" || fail "archive missing mandatory file: $m"
done

zsize="$(stat -c%s "$ZF")"
tsize="$(stat -c%s "$TF")"
[ "$zsize" -gt 102400 ] && [ "$zsize" -lt 10485760 ] \
    || fail "zip size ${zsize} bytes outside plausible source range (100 KiB .. 10 MiB)"
[ "$tsize" -gt 102400 ] && [ "$tsize" -lt 10485760 ] \
    || fail "tar size ${tsize} bytes outside plausible source range (100 KiB .. 10 MiB)"

echo "  zip=${zsize} bytes, tar=${tsize} bytes — clean, verified, inventories identical"
echo "== checksums =="
(cd "$OUT" && sha256sum owntrace-${VERSION}-* | sort -k2 > SHA256SUMS)
echo "== done: $OUT =="
ls -la "$OUT"
