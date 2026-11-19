#!/usr/bin/env bash
#
# mayhem/build.sh — build appsandbox's portable C engines with the fuzz harnesses, plus
# upstream's own engine self-tests (normal flags) for mayhem/test.sh.
#
# Upstream has no Linux build system (MSBuild/Xcode only), so the portable pure-C islands are
# compiled directly, exactly as the Xcode/MSBuild projects list them:
#   tools/iso-patch-mac/engine  WIM reader + LZX, regf/BCD patcher, NTFS/FAT32/GPT writers
#   tools/iso-patch/engine      squashfs reader + vendored xz-embedded (windows.h shim)
#   src/core                    JSON tokenizer, REST validation, MCP JSON-RPC server
# Output goes to mayhem/out/ (gitignored by upstream's [Oo]ut/ rule); targets land in /mayhem.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
MAC=tools/iso-patch-mac/engine
WIN=tools/iso-patch/engine
CORE=src/core
H=mayhem/harnesses
mkdir -p "$OUT/obj" "$OUT/tests"

# Coverage instrumentation for the project code too (not just the harness), when the engine is
# libFuzzer.
COV=""
case "$LIB_FUZZING_ENGINE" in *fuzzer*) COV="-fsanitize=fuzzer-no-link" ;; esac
CFLAGS_FUZZ="$SANITIZER_FLAGS $DEBUG_FLAGS $COV -O1 -D_GNU_SOURCE -std=gnu11"
INC="-I$MAC -I$WIN -I$WIN/xz -I$CORE -I$H"

# wim_extract.c is a standalone CLI (own main). win_disk.c is not linked as an object: its harness
# is a unity build of it (fuzz_win_disk_build.c #includes it, to reset its file-scope state after
# every input).
MAC_SRCS="wim resource wimimg lzx lzms xpress sha1 bcd_patch ntfs fat32 gpt blockio"
XZ_SRCS="xz_crc32 xz_crc64 xz_dec_bcj xz_dec_lzma2 xz_dec_stream"
CORE_SRCS="mcp_server api_json api_contract api_operations asb_events input_router"

# 1) the project, sanitized + instrumented. Each object is compiled in parallel.
compile() { # <src> <obj> <extra flags...>
  local src="$1" obj="$2"; shift 2
  $CC $CFLAGS_FUZZ "$@" -c "$src" -o "$obj"
}
pids=()
# ntfs/fat32/blockio/gpt serve only fuzz-win-disk-build: their allocations go through that harness's
# tracker (mayhem/harnesses/alloc_track.h) so it can free what one build leaves behind.
TRACKED_SRCS="ntfs fat32 gpt blockio"
TRACK="-include $H/alloc_track.h"
for s in $MAC_SRCS; do
  case " $TRACKED_SRCS " in *" $s "*) x="$TRACK" ;; *) x="" ;; esac
  compile "$MAC/$s.c" "$OUT/obj/mac_$s.o" $INC $x & pids+=($!)
done
for s in $XZ_SRCS;  do compile "$WIN/xz/$s.c" "$OUT/obj/xz_$s.o" -I$WIN/xz & pids+=($!); done
# squashfs.c includes <windows.h>: mayhem/shim provides the few file APIs it uses. It reads
# packed on-disk inode fields through casted uint32_t pointers (the block_sizes[] list), which
# trips UBSan's alignment check on every image, valid ones included (harmless on the x86/ARM64
# targets the tool ships for), so only that one check is relaxed, only for this file.
compile "$WIN/squashfs.c" "$OUT/obj/win_squashfs.o" -Imayhem/shim $INC -fno-sanitize=alignment & pids+=($!)
for s in $CORE_SRCS; do compile "$CORE/$s.c" "$OUT/obj/core_$s.o" -I$CORE & pids+=($!); done
compile mayhem/lsan_off.c "$OUT/obj/lsan_off.o" & pids+=($!)
for p in "${pids[@]}"; do wait "$p"; done

objs() { local pfx="$1"; shift; for s in "$@"; do printf '%s ' "$OUT/obj/${pfx}_$s.o"; done; }
WIM_OBJS="$(objs mac wim resource wimimg lzx lzms xpress sha1)"
DISK_OBJS="$(objs mac $MAC_SRCS)"
SQFS_OBJS="$OUT/obj/win_squashfs.o $(objs xz $XZ_SRCS)"
CORE_OBJS="$(objs core $CORE_SRCS)"
API_OBJS="$(objs core api_json api_contract api_operations asb_events input_router)"

# 2) each harness twice: libFuzzer binary + run-once standalone reproducer.
harness() { # <name> <extra -I> <objects...>
  local name="$1" inc="$2"; shift 2
  $CC $CFLAGS_FUZZ $inc -c "$H/fuzz_$name.c" -o "$OUT/obj/fuzz_$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/fuzz_$name.o" "$@" \
      "$OUT/obj/lsan_off.o" -lpthread -lm -o "/mayhem/fuzz_$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "$OUT/obj/fuzz_$name.o" "$@" \
      "$OUT/obj/lsan_off.o" -lpthread -lm -o "/mayhem/fuzz_$name-standalone"
}
harness wim_image      "$INC" $WIM_OBJS
harness lzx_chunk      "$INC" "$OUT/obj/mac_lzx.o"
harness bcd_build      "$INC" "$OUT/obj/mac_bcd_patch.o"
harness vioscsi_hive   "$INC" "$OUT/obj/mac_bcd_patch.o"
harness win_disk_build "$INC" $DISK_OBJS
harness squashfs       "-Imayhem/shim $INC" $SQFS_OBJS
harness mcp_request    "-I$CORE" $CORE_OBJS
harness api_contract   "-I$CORE" $API_OBJS

# 3) upstream's own engine self-tests (tools/iso-patch-mac/engine/test_*.c), normal flags, for
#    mayhem/test.sh. test_fat32 only writes an image (no assertions), so it is not run.
TEST_BASE="-O2 -D_GNU_SOURCE -std=gnu11 $COVERAGE_FLAGS -I$MAC"
$CC $TEST_BASE $MAC/test_ntfs.c     $MAC/ntfs.c $MAC/blockio.c -lm -o "$OUT/tests/test_ntfs"
$CC $TEST_BASE $MAC/test_btree.c    $MAC/ntfs.c $MAC/blockio.c -lm -o "$OUT/tests/test_btree"
$CC $TEST_BASE $MAC/test_resource.c $MAC/wim.c $MAC/resource.c $MAC/lzx.c $MAC/lzms.c $MAC/xpress.c $MAC/sha1.c -o "$OUT/tests/test_resource"
$CC $TEST_BASE $MAC/test_wimimg.c   $MAC/wim.c $MAC/resource.c $MAC/wimimg.c $MAC/lzx.c $MAC/lzms.c $MAC/xpress.c $MAC/sha1.c -o "$OUT/tests/test_wimimg"
$CC $TEST_BASE $MAC/test_bcd.c      $MAC/bcd_patch.c -o "$OUT/tests/test_bcd"
# Known-answer checks for the engines above without an upstream test (mayhem/tests/selftest.c).
$CC $TEST_BASE -Imayhem/shim -I$WIN -I$WIN/xz -I$CORE mayhem/tests/selftest.c \
    $WIN/squashfs.c $WIN/xz/xz_crc32.c $WIN/xz/xz_crc64.c $WIN/xz/xz_dec_bcj.c $WIN/xz/xz_dec_lzma2.c $WIN/xz/xz_dec_stream.c \
    $MAC/bcd_patch.c $MAC/sha1.c \
    $CORE/mcp_server.c $CORE/api_json.c $CORE/api_contract.c $CORE/api_operations.c $CORE/asb_events.c $CORE/input_router.c \
    -lpthread -o "$OUT/tests/selftest"
# The fuzz-win-disk-build harness, normal flags, under a driver that builds one WIM several times in
# one process (mayhem/tests/win_disk_repeat.c): every build must return the same rc and leave nothing.
mkdir -p "$OUT/tests/obj"
for s in $MAC_SRCS; do
  case " $TRACKED_SRCS " in *" $s "*) x="$TRACK" ;; *) x="" ;; esac
  $CC $TEST_BASE -I$H $x -c "$MAC/$s.c" -o "$OUT/tests/obj/$s.o"
done
$CC $TEST_BASE -I$H mayhem/tests/win_disk_repeat.c $H/fuzz_win_disk_build.c \
    $(for s in $MAC_SRCS; do printf '%s ' "$OUT/tests/obj/$s.o"; done) \
    -lpthread -lm -o "$OUT/tests/win_disk_repeat"
echo "build.sh: done"
