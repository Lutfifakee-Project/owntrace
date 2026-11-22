#!/usr/bin/env bash
# Packaging regression test for build-release.sh (v2).
#
# Injects every contamination class the owner reported into a sandbox copy of
# the source tree, runs the ACTUAL packager twice, and asserts:
#   1. no forbidden artifact (nested release archives, release-gate dirs,
#      platform binaries, runtime DBs, tmp files, logs, toolchains, dist,
#      audit dirs) appears in either archive;
#   2. all mandatory source files remain present;
#   3. zip and tar logical inventories match;
#   4. the archive does not contain itself or any nested release archive;
#   5. a second run over the same input and output dir produces a
#      byte-identical zip (no accumulation of generated artifacts);
#   6. the packager REFUSES to run when its output dir is inside staging.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/owntrace-packtest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
pass=0; failn=0
ok()   { echo "  PASS: $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $*"; failn=$((failn+1)); }
assert_fail() { if [ "$1" = 0 ]; then bad "$2"; else ok "$2"; fi; }

echo "== 1. sandbox source copy =="
rsync -a \
    --exclude '/download/' --exclude '/release-gates/' --exclude '/audit-archive/' \
    --exclude '/dist/' --exclude '/owntrace-data/' --exclude '/sec-data/' \
    --exclude '/.toolchain/' --exclude '/.git/' --exclude '/tmp/' \
    --exclude '*.zip' --exclude '*.tar.gz' --exclude '*.db' --exclude '*.log' \
    "$REPO_ROOT/" "$WORK/src/"
src_go="$(find "$WORK/src" -name '*.go' | wc -l)"
echo "  sandbox: $src_go .go files"

echo "== 2. inject contamination fixtures =="
python3 - "$WORK/src" <<'PYEOF'
import os, sys, zipfile, random
root = sys.argv[1]
def blob(path, mb):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    rnd = random.Random(path)
    with open(full, "wb") as fh:
        fh.write(bytes(rnd.getrandbits(8) for _ in range(mb * 1024 * 1024)))
# nested contaminated v0.1.1 gate: source zip + platform binaries (dummy sizes)
blob("download/release-gates/v0.1.1/owntrace-v0.1.1-source.zip", 2)
blob("download/release-gates/v0.1.1/owntrace-v0.1.1-linux-amd64", 1)
blob("download/release-gates/v0.1.1/owntrace-v0.1.1-windows-amd64.exe", 1)
# historical v1.0.0 gate
blob("download/release-gates/v1.0.0/owntrace-v1.0.0-source.zip", 1)
blob("download/release-gates/v1.0.0/owntrace-v1.0.0-darwin-arm64", 1)
# old audit dir, dist dir, toolchain, runtime data, tmp files, logs
blob("audit-archive/old-release.tar.gz", 1)
blob("dist/app.bin", 1)
blob(".toolchain/go1.27.4.tar.gz", 1)
blob("owntrace-data/owntrace.db", 1)
blob("owntrace-data/owntrace.db-wal", 0)
blob("sec-data/evidence.db", 1)
blob("tmp/scratch.txt", 0)
blob("internal/tmp/junk.log", 0)
blob("debug.log", 0)
blob("crash.tmp", 0)
blob("owntrace", 1)                      # stale built binary at tree root
blob("owntrace.exe", 1)                  # stale windows binary
# also one REAL zip whose contents include a nested zip (recursive packaging)
with zipfile.ZipFile(os.path.join(root, "download/nested-real.zip"), "w") as z:
    z.writestr("inner/junk.bin", b"x" * (1024 * 1024))
    z.writestr("inner/owntrace-v0.1.1-source.zip", b"nested-archive-payload")
print("fixtures injected")
PYEOF
echo "  sandbox after injection: $(du -sk "$WORK/src" | cut -f1) KiB"

echo "== 3. run the actual packager (run 1) =="
SKIP_BINARIES=1 SRC="$WORK/src" OUT="$WORK/out" \
    bash "$REPO_ROOT/scripts/build-release.sh" v0.1.1 "$WORK/out" > "$WORK/run1.log" 2>&1 \
    && echo "  packager exit 0" || { cat "$WORK/run1.log"; echo "  packager FAILED"; exit 1; }
Z1="$WORK/out/owntrace-v0.1.1-source.zip"
T1="$WORK/out/owntrace-v0.1.1-source.tar.gz"

echo "== 4. assert archive cleanliness and completeness =="
LIST="$(unzip -Z1 "$Z1")"
# Helper: grep the captured listing (never `unzip | grep` under pipefail, and
# never a bare `grep` statement — `set -e` would exit before assert_fail).
assert_no_match() { grep -qE "$1" <<<"$LIST" && bad "$2" || ok "$2"; }
assert_no_match '(^|/)(download|release-gates|audit-archive|dist|owntrace-data|sec-data|\.toolchain|tmp)(/|$)' "no release-gate/audit/dist/runtime dirs in archive"
assert_no_match '\.(zip|tar\.gz|tgz|db|log|tmp|swp)$' "no nested archives/databases/logs/tmp in archive"
assert_no_match 'FINAL-REPORT|RELEASE-NOTES|acceptance-matrix|(^|/)milestones\.md' "no internal dev-cycle report files in archive"
assert_no_match 'owntrace-v0\.1\.0-source' "archive does not contain itself or another release archive"
assert_no_match '^owntrace/owntrace(\.exe)?$' "no stale built binaries in archive"
zfiles="$(echo "$LIST" | grep -vc '/$')"
src_in_zip="$(echo "$LIST" | grep -c '\.go$')"
test_in_zip="$(echo "$LIST" | grep -c '_test\.go$')"
[ "$src_in_zip" -ge 50 ] && ok "source .go files in archive: $src_in_zip" || bad "only $src_in_zip source files"
[ "$test_in_zip" -ge 20 ] && ok "test .go files in archive: $test_in_zip" || bad "only $test_in_zip test files"
mand=0
for m in go.mod go.sum README.md LICENSE CHANGELOG.md SECURITY.md .gitignore \
         .github/workflows/ci.yml .github/workflows/release-build.yml \
         cmd/owntrace/main.go internal/version/version.go scripts/build-release.sh \
         docs/installation.md docs/architecture.md; do
    echo "$LIST" | grep -qx "owntrace/$m" && mand=$((mand+1)) || bad "missing mandatory $m"
done
[ "$mand" -eq 14 ] && ok "all 14 mandatory files present"
diff <(echo "$LIST" | LC_ALL=C sort) \
     <(tar -tzf "$T1" | grep -v '/$' | LC_ALL=C sort) >/dev/null \
    && ok "zip/tar logical inventories identical ($zfiles files)" || bad "zip/tar inventories differ"

echo "== 5. run the packager AGAIN over the same input and output dir =="
SKIP_BINARIES=1 SRC="$WORK/src" OUT="$WORK/out" \
    bash "$REPO_ROOT/scripts/build-release.sh" v0.1.1 "$WORK/out" > "$WORK/run2.log" 2>&1 \
    && echo "  packager exit 0 (run 2)" || { cat "$WORK/run2.log"; echo "  packager run2 FAILED"; exit 1; }
cmp -s "$Z1" "$WORK/out/owntrace-v0.1.1-source.zip" \
    && ok "run-2 zip byte-identical to run-1 (no accumulation)" || bad "run-2 zip differs from run-1"
z2files="$(unzip -Z1 "$WORK/out/owntrace-v0.1.1-source.zip" | grep -vc '/$')"
[ "$z2files" = "$zfiles" ] && ok "run-2 inventory count unchanged ($z2files)" || bad "run-2 inventory count changed"

echo "== 6. packager must refuse an output dir inside the staged tree =="
set +e
SKIP_BINARIES=1 SRC="$WORK/src" OUT="$WORK/src/out-inside" \
    bash "$REPO_ROOT/scripts/build-release.sh" v0.1.1 "$WORK/src/out-inside" > "$WORK/run3.log" 2>&1
rc3=$?
set -e
assert_fail "$rc3" "output-inside-tree refused (rc=$rc3): $(grep -o 'PACKAGER REFUSED.*' "$WORK/run3.log" | head -1 | cut -c1-80)"

echo "== 7. packager must refuse internal report files in the source tree =="
printf '# internal dev-cycle report\n' > "$WORK/src/FINAL-REPORT.md"
printf '# release notes\n' > "$WORK/src/RELEASE-NOTES-v0.1.1.md"
set +e
SKIP_BINARIES=1 SRC="$WORK/src" OUT="$WORK/out" \
    bash "$REPO_ROOT/scripts/build-release.sh" v0.1.1 "$WORK/out" > "$WORK/run4.log" 2>&1
rc4=$?
set -e
assert_fail "$rc4" "internal-report tree refused (rc=$rc4): $(grep -o 'PACKAGER REFUSED.*' "$WORK/run4.log" | head -1 | cut -c1-80)"
rm -f "$WORK/src/FINAL-REPORT.md" "$WORK/src/RELEASE-NOTES-v0.1.1.md"

echo
echo "PACKAGING REGRESSION TEST: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
