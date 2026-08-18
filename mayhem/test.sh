#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral functional oracle for Lemon.
#
# Upstream ships only a trivial `make test` target (runs test/test_helloworld.lm and checks the
# exit status — it asserts NOTHING about behavior, so a no-op `exit(0)` interpreter would "pass").
# This oracle therefore RUNS pre-built binaries over a set of scripts and compares what they print
# (and their exit status) with the golden results committed under mayhem/tests/ — so a PATCH that
# breaks language behavior (or neuters the program to exit 0) FAILS here. It never compiles anything.
#
# The binaries are the GRADED ones (issue #1460 A): mayhem/build.sh compiles every Lemon source once
# with the graded flags and links those objects into
#   lemon_execute  the Mayhem target `lemon_execute` (mayhem/fuzz_execute.c: compile + run),
#   lemon_compile  the Mayhem target `lemon` (mayhem/fuzz_compile.c: compile only),
#   lemon-oracle   the upstream CLI (src/main.c).
# so no compile-time property (optimization level, sanitizer, NDEBUG, C dialect, ...) differs between
# the code checked here and the code the PoVs replay against, and the targets' own input path
# (lemon_input_set_buffer) is exercised, not only the CLI's (lemon_input_set_file). Every test is
# counted ONCE and passes only if EVERY program it runs gives the expected result, so a patch that
# neuters any one of them fails every test that runs it.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

EXEC="$SRC/lemon_execute"
COMP="$SRC/lemon_compile"
CLI="$SRC/lemon-oracle"
TESTS_DIR="$SRC/mayhem/tests"

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

for bin in "$EXEC" "$COMP" "$CLI"; do
  if [ ! -x "$bin" ]; then
    echo "FATAL: $bin missing — mayhem/build.sh must build it (test.sh does not compile)" >&2
    emit_ctrf "lemon-behavioral" 0 1 0
    exit 1
  fi
done

passed=0
failed=0
why=""        # failure reasons collected for the current test

# expect_output <label> <want-rc> <want-output> <program> <script>: stdout+stderr must equal
# <want-output> exactly and the exit status must be <want-rc>.
expect_output() {
  local label="$1" want_rc="$2" want="$3" got rc
  got="$("$4" "$5" 2>&1)"; rc=$?
  if [ "$rc" -ne "$want_rc" ] || [ "$got" != "$want" ]; then
    why+="  --- $label: exit $rc (want $want_rc) ---"$'\n'"  expected:"$'\n'"$(printf '%s\n' "$want" | sed 's/^/    /')"$'\n'"  got:"$'\n'"$(printf '%s\n' "$got" | sed 's/^/    /')"$'\n'
  fi
}

# expect_rejected <label> <diagnostic> <program> <script>: the program must exit 1 and report
# "<file>:<diagnostic>" (Lemon's own `<file>:<line>:<col>: error: <message>` line) — and must not
# have crashed doing so (a sanitizer abort also exits 1 by default, so its report is checked for).
expect_rejected() {
  local label="$1" diag="$2" got rc
  got="$("$3" "$4" 2>&1)"; rc=$?
  if [ "$rc" -ne 1 ] || ! printf '%s\n' "$got" | grep -qF -- ":$diag" \
     || printf '%s\n' "$got" | grep -qE 'ERROR: [A-Za-z]+Sanitizer|runtime error:|SUMMARY: [A-Za-z]+Sanitizer'; then
    why+="  --- $label: exit $rc (want 1), want a line containing \":$diag\" and no sanitizer report ---"$'\n'"$(printf '%s\n' "$got" | sed 's/^/    /')"$'\n'
  fi
}

finish() {    # finish <test name>
  if [ -z "$why" ]; then
    echo "PASS $1"
    passed=$((passed + 1))
  else
    echo "FAIL $1"
    printf '%s' "$why"
    failed=$((failed + 1))
  fi
  why=""
}

# ── Golden-output behavioral tests: each script must RUN to its recorded output (exit 0) through
#    the execute target and the CLI, and COMPILE silently (exit 0, no output) through the compile
#    target. ────────────────────────────────────────────────────────────────────────────────────
for exp in "$TESTS_DIR"/*.expected; do
  name="$(basename "$exp" .expected)"
  script="$TESTS_DIR/$name.lm"
  want="$(cat "$exp")"
  expect_output lemon_execute 0 "$want" "$EXEC" "$script"
  expect_output lemon-oracle  0 "$want" "$CLI"  "$script"
  expect_output lemon_compile 0 ""      "$COMP" "$script"
  finish "golden:$name"
done

# ── Upstream suite: test/test_helloworld.lm (the only runnable upstream test), asserted on output.
#    CLI only: it imports './test.lm', which Lemon resolves next to the input file's real path —
#    the targets name their in-memory input "fuzz.lm", so they cannot resolve a relative import.
if [ -f "$SRC/test/test_helloworld.lm" ]; then
  expect_output lemon-oracle 0 "Hello World" "$CLI" test/test_helloworld.lm
  finish "upstream:test_helloworld"
fi

# ── Negative tests: an invalid script must be REJECTED — exit status 1 plus Lemon's diagnostic at
#    the right line:column — by all three programs, not swallowed. Each errors/<name>.lm has the
#    expected diagnostic in errors/<name>.diag (lexer, parser and compiler errors). ──────────────
for diagf in "$TESTS_DIR"/errors/*.diag; do
  name="$(basename "$diagf" .diag)"
  script="$TESTS_DIR/errors/$name.lm"
  diag="$(cat "$diagf")"
  expect_rejected lemon_execute "$diag" "$EXEC" "$script"
  expect_rejected lemon-oracle  "$diag" "$CLI"  "$script"
  expect_rejected lemon_compile "$diag" "$COMP" "$script"
  finish "negative:$name"
done

emit_ctrf "lemon-behavioral" "$passed" "$failed" 0
