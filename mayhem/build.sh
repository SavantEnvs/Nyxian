#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Nyxian ships only an Xcode/iOS build (no Linux target, no upstream fuzzers or tests). The plain-C/C++
# parsers that read untrusted data are compiled directly from the tree, with tiny Darwin stand-in
# headers in mayhem/shim (mach-o/*, CommonCrypto -> OpenSSL, opaque CoreFoundation types).
OUT="$SRC/mayhem/out"           # gitignored build dir (removed by `git clean -ffdX`)
mkdir -p "$OUT/obj" "$OUT/test"
PS="$SRC/Nyxian/LindChain/ProcEnvironment"
TRUST="$PS/Surface/trust"
RADIX="$PS/Surface/libkern/radix"
ZS="$PS/LiveContainer/ZSign"
SHIM="$SRC/mayhem/shim"
H="$SRC/mayhem/harnesses"

NYX_CFLAGS="-I$SHIM -I$SRC/Nyxian -I$SRC -include $SHIM/nyx_pre.h -Wno-import-preprocessor-directive-pedantic -Wno-#warnings"
ZS_CXXFLAGS="-std=c++17 -I$ZS/common -I$ZS -include cstdint -w"
FUZZ="$SANITIZER_FLAGS $DEBUG_FLAGS"
# SanCov on the project objects and harnesses (libFuzzer's runtime is linked only into the fuzzers)
COV="-fsanitize=fuzzer-no-link"
# zsign reads bplist / Mach-O fields through casted pointers at arbitrary input offsets. With the
# alignment check on, the shipped seed mayhem/zsign_plist/testsuite/info.bplist aborts at once in
# json.cpp:2508:26 jpreader::_get_uint_val (`*((uint64_t*)v)`, an 8-byte offset-table entry at
# 0x...4a); bplist offset tables are byte-packed, so this is the normal case. Misaligned loads are benign on x86-64/arm64, so only
# UBSan's alignment check is relaxed for zsign. ASan and the rest of UBSan stay halting.
ZS_FUZZ_CXXFLAGS="$ZS_CXXFLAGS -fno-sanitize=alignment"

cc_obj()  { $CC  $FUZZ $COV $NYX_CFLAGS -c "$1" -o "$2"; }
cxx_obj() { $CXX $FUZZ $COV $ZS_FUZZ_CXXFLAGS -c "$1" -o "$2"; }

# 1) the project code, instrumented
cc_obj  "$TRUST/cdhash.c"           "$OUT/obj/cdhash.o"
$CC $FUZZ $COV $NYX_CFLAGS -DCLIENT_ENV=1 -D__NXTOOL=1 -c "$TRUST/apple.c" -o "$OUT/obj/apple.o"
cc_obj  "$RADIX/radix.c"            "$OUT/obj/radix.o"
# NXT2 trust blob + vendor key reader, in the nxtool host configuration (no iOS signature check)
$CC $FUZZ $COV $NYX_CFLAGS -D__NXTOOL=1 -DHOST_ENV=1 -c "$TRUST/signing.c" -o "$OUT/obj/signing.o"
cc_obj  "$SHIM/cf_stub.c"           "$OUT/obj/cf_stub.o"
cc_obj  "$SHIM/cc_openssl.c"        "$OUT/obj/cc_openssl.o"
cxx_obj "$ZS/common/json.cpp"       "$OUT/obj/json.o"
cxx_obj "$ZS/common/base64.cpp"     "$OUT/obj/base64.o"
# zsign Mach-O signer: F_FULLFSYNC is Darwin-only (used when writing a signed file, never on the
# parse path); Utils.mm is Objective-C++, replaced by mayhem/shim/zsign_utils_stub.cpp
ZS_OBJS=()
for f in "$ZS/archo.cpp" "$ZS/signing.cpp" "$ZS/openssl.cpp" "$ZS/common/sha.cpp" "$ZS/common/log.cpp" \
         "$ZS/common/util.cpp" "$ZS/common/fs.cpp" "$ZS/common/timer.cpp" "$SHIM/zsign_utils_stub.cpp"; do
    o="$OUT/obj/zs_$(basename "$f" .cpp).o"
    $CXX $FUZZ $COV $ZS_FUZZ_CXXFLAGS -DF_FULLFSYNC=F_GETFL -c "$f" -o "$o"
    ZS_OBJS+=("$o")
done
$CXX $FUZZ -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/obj/lsan_off.o"
$CC  $FUZZ -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/obj/standalone_main.o"

# 2) harnesses: libFuzzer binary + run-once standalone reproducer each
link() {  # name lang objs...
    local name="$1" lang="$2"; shift 2
    local src="$H/$name.${lang}" comp
    if [ "$lang" = c ]; then
        $CC $FUZZ $COV $NYX_CFLAGS -c "$src" -o "$OUT/obj/$name.o"
    else
        $CXX $FUZZ $COV $ZS_FUZZ_CXXFLAGS -c "$src" -o "$OUT/obj/$name.o"
    fi
    $CXX $FUZZ $LIB_FUZZING_ENGINE "$OUT/obj/$name.o" "$@" "$OUT/obj/lsan_off.o" -lcrypto -lm -o "$SRC/mayhem/$name"
    $CXX $FUZZ $COV "$OUT/obj/standalone_main.o" "$OUT/obj/$name.o" "$@" "$OUT/obj/lsan_off.o" -lcrypto -lm \
        -o "$SRC/mayhem/$name-standalone"
}
link fuzz_cdhash       c   "$OUT/obj/cdhash.o" "$OUT/obj/cc_openssl.o"
link fuzz_cdhash_match c   "$OUT/obj/apple.o" "$OUT/obj/cdhash.o" "$OUT/obj/cc_openssl.o"
link fuzz_radix        c   "$OUT/obj/radix.o"
link fuzz_nxt2_read    c   "$OUT/obj/signing.o" "$OUT/obj/cdhash.o" "$OUT/obj/cf_stub.o" "$OUT/obj/cc_openssl.o"
link fuzz_nxt2_pubkey  c   "$OUT/obj/signing.o" "$OUT/obj/cdhash.o" "$OUT/obj/cf_stub.o" "$OUT/obj/cc_openssl.o"
link fuzz_zsign_json   cpp "$OUT/obj/json.o" "$OUT/obj/base64.o"
link fuzz_zsign_plist  cpp "$OUT/obj/json.o" "$OUT/obj/base64.o"
link fuzz_zsign_macho  cpp "${ZS_OBJS[@]}" "$OUT/obj/json.o" "$OUT/obj/base64.o"

# 3) known-answer driver for test.sh, with normal (unsanitized) flags
T="$OUT/test"
$CC  -O1 $COVERAGE_FLAGS $NYX_CFLAGS -c "$TRUST/cdhash.c"    -o "$T/cdhash.o"
$CC  -O1 $COVERAGE_FLAGS $NYX_CFLAGS -c "$RADIX/radix.c"     -o "$T/radix.o"
$CC  -O1 $COVERAGE_FLAGS $NYX_CFLAGS -c "$SHIM/cc_openssl.c" -o "$T/cc_openssl.o"
$CC  -O1 $COVERAGE_FLAGS $NYX_CFLAGS -D__NXTOOL=1 -DHOST_ENV=1 -c "$TRUST/signing.c" -o "$T/signing.o"
$CC  -O1 $COVERAGE_FLAGS $NYX_CFLAGS -c "$SHIM/cf_stub.c" -o "$T/cf_stub.o"
$CXX -O1 $COVERAGE_FLAGS $ZS_CXXFLAGS -c "$ZS/common/json.cpp"   -o "$T/json.o"
$CXX -O1 $COVERAGE_FLAGS $ZS_CXXFLAGS -c "$ZS/common/base64.cpp" -o "$T/base64.o"
$CXX -O1 $COVERAGE_FLAGS $ZS_CXXFLAGS -I"$SRC/Nyxian" -I"$SRC" -include "$SHIM/nyx_pre.h" \
    -I"$SHIM" -D__NXTOOL=1 -DHOST_ENV=1 -c "$SRC/mayhem/test/nyx_selftest.cpp" -o "$T/nyx_selftest.o"
$CXX $COVERAGE_FLAGS "$T"/nyx_selftest.o "$T"/cdhash.o "$T"/radix.o "$T"/cc_openssl.o "$T"/signing.o "$T"/cf_stub.o "$T"/json.o "$T"/base64.o \
    -lcrypto -o "$T/nyx_selftest"
