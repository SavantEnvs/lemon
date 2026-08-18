/*
 * fuzz_execute.c -- per-input entry point of the Mayhem target `lemon_execute`
 * (/mayhem/lemon_execute, linked with mayhem/raw_main.c, which reads the `@@`
 * file and calls RunOneTest() once). It drives the Lemon compiler's FULL
 * pipeline: compile AND run the untrusted source through
 * lemon_machine_execute() (the bytecode VM), unlike mayhem/fuzz_compile.c
 * which stops at the front end. This is the DEEP target -- it drives the
 * interpreter loop, the collector (GC), and the l* runtime object model
 * (arrays, dicts, closures, coroutines, exceptions, ...), not just
 * lex/parse/compile.
 *
 * ---- bounding: none in the harness (issue #1298) ----
 *
 * This file arms NO timer, alarm or signal handler of any kind. A script
 * that never terminates (`while (true) {}`, an unbounded `for`) is bounded
 * by the RUNNER: Mayhem kills the process when the explicit per-test
 * `timeout:` on the cmd in mayhem/Mayhemfile_lemon_execute expires. A
 * harness-side wall-clock watchdog would make the verdict for an input
 * depend on machine load (a crash behind slow-but-legitimate work would be
 * turned into a clean exit, or its sanitizer report cut short).
 *
 * NO HOST BINDINGS: unlike mayhem/fuzz_compile.c (which registers the `os`
 * and `socket` builtin modules purely so `import 'os'`/`import 'socket'`
 * resolve identically to the real CLI during front-end fuzzing, where
 * nothing is ever executed), this EXECUTE harness deliberately does NOT
 * register them:
 *   - os.exit(n) calls the libc exit(3) directly (lib/os.c) -- reachable
 *     from any fuzzed script, it would end the process from inside the
 *     script with a status of the script's choosing (a self-inflicted, not
 *     a memory-safety, "finding"; and rlenv would read an os.exit(0) inside
 *     RunOneTest() as a premature exit, see mayhem/raw_main.c).
 *   - the `socket` module exposes real socket()/bind()/listen()/connect()/
 *     accept()/send()/recv() (lib/socket.c) -- untrusted-script-triggered
 *     network I/O has no place in a fuzz harness.
 * `import 'os'`/`import 'socket'` therefore resolve to nil in this harness,
 * and any subsequent `.member` access on that nil is the ordinary
 * attribute-on-nil path already exercised by countless other inputs -- not
 * a defect specific to this harness's module configuration.
 *
 * The library calls per input are unchanged from the libFuzzer-shaped
 * harness this replaces (issue #1313): only the function's name and its
 * return value differ -- 1 when lemon_compile() rejects the script, else 0
 * after the program ran (the upstream CLI's exit status convention, see
 * src/main.c). See mayhem/raw_main.c for why the target is a raw file-input
 * program and why the function is named RunOneTest.
 *
 * A fresh struct lemon (and its own allocator arena) is created and
 * destroyed every call, so VM/heap state never accumulates across inputs.
 */
#include "lemon.h"
#include "input.h"
#include "lstring.h"
#include "lib/builtin.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int RunOneTest(const uint8_t *data, size_t size);

int
RunOneTest(const uint8_t *data, size_t size)
{
	struct lemon *lemon;
	char *buffer;
	int compiled;

	lemon = lemon_create();
	if (!lemon) {
		return 0;
	}
	builtin_init(lemon);
	/* Deliberately NOT registering the `os`/`socket` modules -- see the
	 * file header ("NO HOST BINDINGS"). */

	/*
	 * lemon_input_set_buffer stores the pointer directly (no copy) and
	 * reads up to `size` bytes; keep a private, NUL-terminated copy alive
	 * across compile+execute and free it afterwards (lemon_destroy does
	 * not own it).
	 */
	buffer = malloc(size + 1);
	if (!buffer) {
		lemon_destroy(lemon);
		return 0;
	}
	if (size) {
		memcpy(buffer, data, size);
	}
	buffer[size] = '\0';

	lemon_input_set_buffer(lemon, "fuzz.lm", buffer, (int)size);

	compiled = lemon_compile(lemon);
	if (compiled) {
		lemon_machine_reset(lemon);
		lemon_machine_execute(lemon);
	}

	lemon_destroy(lemon);
	free(buffer);

	return compiled ? 0 : 1;
}
