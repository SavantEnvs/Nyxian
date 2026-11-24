#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# Nyxian ships no test suite (iOS-only Xcode project). mayhem/test/nyx_selftest (built by build.sh with
# normal flags) runs the same parsers the fuzz targets reach; each case diffs its output against a known
# answer. The cdhash goldens are SHA-1/256/384 of the CodeDirectory bytes, computed independently.
T="$SRC/mayhem/test"
BIN="$SRC/mayhem/out/test/nyx_selftest"
[ -x "$BIN" ] || { echo "missing $BIN — mayhem/build.sh must build it" >&2; emit_ctrf nyx-selftest 0 1; exit 1; }

passed=0; failed=0
check() {  # name expected cmd...
  local name="$1" exp="$2"; shift 2
  local got; got="$("$@" 2>&1)"
  if [ "$got" == "$exp" ]; then passed=$((passed+1)); echo "PASS $name"
  else failed=$((failed+1)); echo "FAIL $name"; echo "  expected: $exp"; echo "  got:      $got"; fi
}

check cdhash_thin_sha256 77cb74fd0cccab03dbb8e00c80404394f4b7de91 "$BIN" cdhash "$T/thin_sha256.macho"
check cdhash_thin_sha1   a57f7983bfc1ae6328f076055c3c8455f1e271d2 "$BIN" cdhash "$T/thin_sha1.macho"
check cdhash_best_of_alternates d27c9ee2febe23609732997ca505fc843617bf49 "$BIN" cdhash "$T/thin_multi.macho"
check cdhash_fat32       77cb74fd0cccab03dbb8e00c80404394f4b7de91 "$BIN" cdhash "$T/fat32.macho"
check cdhash_fat64       4a1e4238497889a1b1e3a31099de9ba8c0996b7d "$BIN" cdhash "$T/fat64.macho"
check cdhash_rejects_bad_codedirectory none "$BIN" cdhash "$T/thin_badcd.macho"
check zsign_json_roundtrip '{"list":[1,2.5,true,null,"xA"],"name":"Nyxian","nested":{"k":-7}}' "$BIN" json "$T/doc.json"
check zsign_plist_entitlements '{"application-identifier":"ABCDE12345.com.example.app","get-task-allow":true,"keychain-access-groups":["ABCDE12345.*"],"version":42}' "$BIN" plist "$T/entitlements.plist"
check nxt2_trailer_parsed 'kr=0 valid=1 cdhash_valid=0 signed=0 plist=126' "$BIN" nxt2 "$T/nxt2_signed.bin"
check nxt2_missing_trailer_rejected 'kr=5 valid=0 cdhash_valid=0 signed=0 plist=-1' "$BIN" nxt2 "$T/thin_sha256.macho"
check nxt2_vendor_pubkey 'kr=0 vendor=Example Vendor keylen=91' "$BIN" pubkey "$T/vendor.pub"
check nxt2_vendor_pubkey_rejects_garbage 'kr=5 vendor=- keylen=0' "$BIN" pubkey "$T/doc.json"
check radix_insert_remove_walk "$(printf 'lookup2=6 lookup300=0\n1=1\n2=6\n10000=4\ndeadbeefcafe=5')" "$BIN" radix

emit_ctrf nyx-selftest "$passed" "$failed"
