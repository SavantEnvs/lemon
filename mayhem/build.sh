#!/usr/bin/env bash
#
# mayhem/build.sh — build the Lemon Mayhem targets and the binaries mayhem/test.sh runs.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. Everything is
# ADDITIVE: no upstream file is edited. Outputs:
#   /mayhem/lemon_compile  target `lemon` (mayhem/Mayhemfile): RAW file-input program
#                          (mayhem/raw_main.c + mayhem/fuzz_compile.c) that compiles the `@@` script
#                          with the Lemon front end (lexer -> parser -> compiler -> peephole ->
#                          codegen) and does not run it.
#   /mayhem/lemon_execute  target `lemon_execute` (mayhem/Mayhemfile_lemon_execute): RAW file-input
#                          program (mayhem/raw_main.c + mayhem/fuzz_execute.c) that compiles AND
#                          RUNS the script (lemon_machine_execute: VM, collector, object model).
#   /mayhem/lemon-oracle   the upstream `lemon` CLI (src/main.c), for mayhem/test.sh.
# Each target binary is its own reproducer (`<binary> <file>`, one process per input), so there is
# no separate -standalone binary.
#
# WHY RAW FILE-INPUT PROGRAMS, NOT libFuzzer (issue #1313): Lemon has real, shallow crashes (a 1-byte
# `-` or `!` overflows the parser's stack; `var ;` NULL-derefs at src/compiler.c:1009) and both
# targets' accumulated server-side corpora contain such inputs (11 of 467 for `lemon`, 18 of 455 for
# `lemon_execute` when #1313 was fixed). An in-process libFuzzer run aborts while loading that corpus
# (Mayhem: "libFuzzer target failed to fuzz for 5 iterations" -> critical error, run failed), whereas a
# per-input process reports each such input as a defect and keeps fuzzing. So each target is a real
# program with its own main() and no libFuzzer entry point, compiled with -fsanitize=fuzzer-no-link
# (SanitizerCoverage edge counters without the libFuzzer runtime; plain ASan+UBSan records 0 edges)
# and bounded only by the explicit per-test `timeout:` in its Mayhemfile (no harness timer, #1298).
#
# ONE BUILD OF THE PROJECT CODE, AND test.sh RUNS THE GRADED BINARIES (the issue #1460 A pattern):
# every Lemon source is compiled exactly ONCE, into one object, with the graded flags
# ($SANITIZER_FLAGS, the narrow UBSan relax below, -fsanitize=fuzzer-no-link, $DEBUG_FLAGS, Lemon's
# defines), and the same objects are linked into both targets and into lemon-oracle. There is no
# separate test build: mayhem/test.sh checks every script through lemon_execute, lemon_compile AND
# lemon-oracle. (The previous oracle was upstream's own -std=c89 -O2 -DNDEBUG build, and only it ran
# in test.sh, so a patch gated on a build difference — `#ifndef __OPTIMIZE__`,
# `__has_feature(address_sanitizer)`, NDEBUG, __STDC_VERSION__ — or on the harness-only input path
# (lemon_input_set_buffer; the CLI loads files with lemon_input_set_file) could neuter Lemon exactly
# where the PoVs replay while test.sh stayed 7/7.)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

# Relax ONLY the benign UBSan `nonnull-attribute` check, keeping ASan and the rest of UBSan
# halting. Lemon's parser makes an empty NAME/NUMBER syntax node for a zero-length token (e.g. the
# name after a stray token like `@`): syntax_make_name_node()/syntax_make_number_node()
# (src/syntax.c) call `memcpy(dst, buffer, length)` with buffer=NULL, length=0. That is harmless
# (a 0-byte copy) but trips UBSan's nonnull-attribute check (memcpy declares its src non-null) on
# essentially every non-trivial input, aborting exploration before it starts. This is the
# sanctioned narrow relax (PORTING.md "benign UB that floods under halting UBSan"); real
# memory-safety UB (out-of-bounds/UAF via ASan; signed overflow, shifts, etc. via the rest of
# UBSan) still halts and is reported as a defect.
UBSAN_RELAX="-fno-sanitize=nonnull-attribute"

cd "$SRC"

# Lemon's own compile-time definitions (the upstream Makefile's Linux build, with both built-in
# modules enabled). Upstream's -std=c89 -pedantic is not used: the sanitizer instrumentation and
# clang extensions need the compiler's default C dialect. The same set applies to every object.
LEMON_DEFS="-DLINUX -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -DMODULE_OS -DMODULE_SOCKET -DSTATICLIB"
LEMON_INCS="-I$SRC -I$SRC/src"

# The library sources exactly as the upstream Makefile's SRCS lists them (src/main.c, the CLI entry,
# is linked only into lemon-oracle; opcode.c is not part of the library, matching upstream).
LIB_SRCS=(
  src/lemon.c src/hash.c src/shell.c src/mpool.c src/arena.c src/table.c src/token.c
  src/input.c src/lexer.c src/scope.c src/syntax.c src/parser.c src/symbol.c src/extend.c
  src/compiler.c src/peephole.c src/generator.c src/allocator.c src/collector.c src/machine.c
  src/lnil.c src/ltype.c src/lkarg.c src/lvarg.c src/ltable.c src/lvkarg.c src/larray.c
  src/lframe.c src/lclass.c src/lsuper.c src/lobject.c src/lmodule.c src/lnumber.c src/lstring.c
  src/linteger.c src/lboolean.c src/linstance.c src/literator.c src/lfunction.c src/lsentinel.c
  src/laccessor.c src/lexception.c src/lcoroutine.c src/ldictionary.c src/lcontinuation.c
  lib/builtin.c lib/os.c lib/socket.c
)
# mayhem/lsan_off.c: LeakSanitizer is disabled at BUILD time (never via runtime options) by its
# __lsan_is_turned_off() hook, linked into every binary below; ASan and the rest of UBSan stay on and
# halting. See that file for lemon's known upstream allocator leak.
MAYHEM_SRCS=(mayhem/raw_main.c mayhem/fuzz_compile.c mayhem/fuzz_execute.c mayhem/lsan_off.c)

# The flags every object is compiled with. $COVERAGE_FLAGS is empty by default (no effect); a
# source-coverage measurement build (--build-arg COVERAGE_FLAGS="-fprofile-instr-generate
# -fcoverage-mapping", never used for fuzzing or grading) instruments every object and binary,
# since there is no separate test build.
COMPILE_FLAGS="$SANITIZER_FLAGS $UBSAN_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS $COVERAGE_FLAGS -fPIC $LEMON_DEFS $LEMON_INCS"
LINK_FLAGS="$SANITIZER_FLAGS $UBSAN_RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS $COVERAGE_FLAGS"

# Objects go to a private scratch dir (never into the source tree), removed on exit; every run
# recompiles everything from source, so build.sh is idempotent and clean-tree-safe.
OBJ="$(mktemp -d "${TMPDIR:-/tmp}/lemon-build.XXXXXX")"
trap 'rm -rf "$OBJ"' EXIT
obj() { local o="${1//\//_}"; printf '%s/%s.o' "$OBJ" "${o%.c}"; }

echo ">> compiling Lemon + mayhem/ sources once (ASan+UBSan halting, SanCov edges, DWARF-3)"
export OBJ COMPILE_FLAGS
# shellcheck disable=SC2016
printf '%s\n' "${LIB_SRCS[@]}" src/main.c "${MAYHEM_SRCS[@]}" \
  | xargs -P "$MAYHEM_JOBS" -n 1 bash -c 'o="${1//\//_}"; exec $CC $COMPILE_FLAGS -c "$1" -o "$OBJ/${o%.c}.o"' _

LIB_OBJS=()
for s in "${LIB_SRCS[@]}"; do LIB_OBJS+=("$(obj "$s")"); done

link() {   # link <output> <extra objects...>
  local out="$1"; shift
  # shellcheck disable=SC2086
  "$CC" $LINK_FLAGS "${LIB_OBJS[@]}" "$@" "$(obj mayhem/lsan_off.c)" -lm -ldl -o "$out"
}
echo ">> linking /mayhem/lemon_compile (target lemon), /mayhem/lemon_execute (target lemon_execute), /mayhem/lemon-oracle (CLI)"
link /mayhem/lemon_compile "$(obj mayhem/raw_main.c)" "$(obj mayhem/fuzz_compile.c)"
link /mayhem/lemon_execute "$(obj mayhem/raw_main.c)" "$(obj mayhem/fuzz_execute.c)"
link /mayhem/lemon-oracle  "$(obj src/main.c)"

echo ">> build.sh done: /mayhem/lemon_compile /mayhem/lemon_execute (targets + reproducers) /mayhem/lemon-oracle (test.sh)"
