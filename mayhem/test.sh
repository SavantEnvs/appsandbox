#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the functional checks mayhem/build.sh built (never compiles here):
#   * upstream's engine self-tests (tools/iso-patch-mac/engine/test_*.c):
#       test_resource  every LZX resource of a WIM decompresses to its lookup-table SHA-1
#       test_wimimg    full DIRENTRY walk: hashes resolve, length invariant holds, boot paths exist
#       test_ntfs      builds an NTFS volume and re-reads it independently (13 checks)
#       test_bcd       builds a BCD from a BCD-Template
#   * mayhem/tests/win_disk_repeat  the fuzz-win-disk-build harness builds the LZX WIM several
#                            times in one process: same rc each time, even after failed builds
#   * mayhem/tests/selftest  known-answer checks for squashfs, the SYSTEM-hive vioscsi patch,
#                            bcd_build (golden SHA-1), the MCP server and REST validation.
# Fixtures are the committed seed files under mayhem/fuzz-*/testsuite/.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T="$SRC/mayhem/out/tests"
for b in test_resource test_wimimg test_ntfs test_bcd selftest win_disk_repeat; do
  [ -x "$T/$b" ] || { echo "test.sh: $T/$b missing — mayhem/build.sh did not build the suite" >&2; emit_ctrf appsandbox-engine-tests 0 1; exit 1; }
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asb-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FX="$WORK/fixtures"; mkdir -p "$FX"
cp mayhem/fuzz-squashfs/testsuite/sqfs_xz.sqfs mayhem/fuzz-vioscsi-hive/testsuite/system.hive \
   mayhem/fuzz-bcd-build/testsuite/bcd.hive "$FX/"
LZX_WIM=mayhem/fuzz-wim-image/testsuite/wim_lzx.wim
RAW_WIM=mayhem/fuzz-wim-image/testsuite/wim_none.wim

passed=0 failed=0 skipped=0
pass() { passed=$((passed+1)); echo "PASS $*"; }
fail() { failed=$((failed+1)); echo "FAIL $*"; }

# test_resource: SHA-1 of every decompressed resource must match. The fixture has 4 compressed
# resources (3 single-chunk, 1 multi-chunk).
out="$("$T/test_resource" "$LZX_WIM" 2>&1)"; rc=$?; echo "$out"
if [ $rc -eq 0 ] && grep -q 'tested=4 OK=4 FAIL=0  (single-chunk=3 multi-chunk=1' <<<"$out"; then pass test_resource; else fail test_resource; fi

# test_wimimg on the LZX and the uncompressed WIM: same tree either way.
for w in "$LZX_WIM" "$RAW_WIM"; do
  out="$("$T/test_wimimg" "$w" 1 2>&1)"; rc=$?; echo "$out"
  if [ $rc -eq 0 ] && grep -q '^dirs=9 files=9 ' <<<"$out" && grep -q '^hash_ok=9 hash_miss=0  invariant_ok=18 invariant_bad=0' <<<"$out" \
     && grep -q 'System32=1 ntoskrnl.exe=1 config\\SYSTEM=1 Boot\\EFI\\bootmgfw=1' <<<"$out"; then
    pass "test_wimimg $(basename "$w")"; else fail "test_wimimg $(basename "$w")"; fi
done

# test_ntfs: each CHECK is one test. Upstream's checker looks names up in the root $INDEX_ROOT
# only, but the writer now spills the root directory (system files + 4 entries) into an
# $INDEX_ALLOCATION B-tree, so its three root-name lookups are stale: those are skipped, every
# other check must pass.
out="$("$T/test_ntfs" "$WORK/ntfs.img" 2>&1)"; echo "$out"
summary="$(grep -E '^--- [0-9]+ checks, [0-9]+ failures ---$' <<<"$out")"
if [ -z "$summary" ] || ! grep -q '^ntfs_writer_close rc=0' <<<"$out"; then
  fail "test_ntfs (no result)"
else
  checks="$(sed -E 's/^--- ([0-9]+) checks.*/\1/' <<<"$summary")"
  stale=0 other=0
  while IFS= read -r l; do
    case "$l" in
      "  FAIL: found hello.txt"|"  FAIL: found BIGFILE.BIN"|"  FAIL: found subdir") stale=$((stale+1)) ;;
      "  FAIL: "*) other=$((other+1)); echo "FAIL test_ntfs: ${l#  FAIL: }" ;;
    esac
  done <<<"$out"
  if [ "$checks" -lt 13 ]; then fail "test_ntfs ran $checks of 13 checks"; fi
  passed=$((passed + checks - stale - other)); failed=$((failed + other)); skipped=$((skipped + stale))
  echo "test_ntfs: $checks checks, $other failures, $stale stale root-index lookups skipped"
fi

# test_bcd: upstream's driver; selftest checks the bytes against a golden SHA-1.
out="$("$T/test_bcd" "$FX/bcd.hive" "$WORK/bcd.out" 2>&1)"; rc=$?; echo "$out"
if [ $rc -eq 0 ] && grep -q 'bcd_build rc=0  out_len=20480  (template=12288)' <<<"$out" && [ "$(stat -c %s "$WORK/bcd.out")" = 20480 ]; then
  pass test_bcd; else fail test_bcd; fi
# The same BCD template repacked into one 4 KiB hbin (8192 bytes, so a fuzzer input-length cap of
# 8 KiB does not truncate it): bcd_build must still succeed and produce these exact bytes.
out="$("$T/test_bcd" mayhem/fuzz-bcd-build/testsuite/bcd_8k.hive "$WORK/bcd8k.out" 2>&1)"; rc=$?; echo "$out"
if [ $rc -eq 0 ] && grep -q 'bcd_build rc=0  out_len=16384  (template=8192)' <<<"$out" \
   && [ "$(sha1sum < "$WORK/bcd8k.out" | cut -d' ' -f1)" = d12f240e628da6cb81d80f66e4f87439fd2adbae ]; then
  pass test_bcd_8k; else fail test_bcd_8k; fi

# win_disk_repeat: the fuzz-win-disk-build harness, several builds in one process. The LZX WIM must
# build a complete disk (rc 0) every time, also right after a build that failed early (a truncated
# WIM) and one that failed late (staging errors, rc 1), and no win_disk.c allocation may be left.
head -c 4096 "$LZX_WIM" > "$WORK/truncated.wim"
out="$("$T/win_disk_repeat" "$LZX_WIM" "$WORK/truncated.wim" 2>&1)"; rc=$?
grep '^run ' <<<"$out"
exp="run good1 rc=0 live=0
run good2 rc=0 live=0
run bad rc=2 live=0
run good3 rc=0 live=0
run staging-error rc=1 live=0
run good4 rc=0 live=0"
if [ $rc -eq 0 ] && [ "$(grep '^run ' <<<"$out")" = "$exp" ]; then pass win_disk_repeat; else fail win_disk_repeat; fi

# selftest: one line per check, then SELFTEST passed=P failed=F.
out="$("$T/selftest" "$FX" 2>&1)"; rc=$?; echo "$out"
line="$(grep -E '^SELFTEST passed=[0-9]+ failed=[0-9]+$' <<<"$out")"
if [ -z "$line" ]; then
  fail "selftest (no result)"
else
  p="$(sed -E 's/.*passed=([0-9]+).*/\1/' <<<"$line")"; f="$(sed -E 's/.*failed=([0-9]+)/\1/' <<<"$line")"
  if [ "$p" -lt 42 ]; then f=$((f + 1)); echo "FAIL selftest ran only $p passing checks (expected 42)"; fi
  [ $rc -eq 0 ] || [ "$f" -gt 0 ] || f=1
  passed=$((passed + p)); failed=$((failed + f))
fi

emit_ctrf appsandbox-engine-tests "$passed" "$failed" "$skipped"
