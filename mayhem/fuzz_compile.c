/*
 * fuzz_compile.c -- per-input entry point of the Mayhem target `lemon` (/mayhem/lemon_compile,
 * linked with mayhem/raw_main.c, which reads the `@@` file and calls RunOneTest() once).
 *
 * RunOneTest() feeds the input bytes straight to lemon_compile(), exercising the SAME front-end
 * code path as the upstream `lemon` CLI -- lexer, parser, compiler, peephole optimizer, bytecode
 * generator and collector -- WITHOUT running the compiled bytecode (no lemon_machine_execute):
 * executing attacker-controlled scripts is the job of the `lemon_execute` target
 * (mayhem/fuzz_execute.c); this one keeps the front end's own crashes separate from the VM's. The
 * `os` and `socket` builtin modules are registered exactly as the CLI does, so `import 'os'` /
 * `import 'socket'` resolve identically during compilation (nothing is ever executed here).
 *
 * The library calls per input are unchanged from the libFuzzer-shaped harness this replaces
 * (issue #1313): only the function's name and its return value differ -- it now returns 1 when
 * lemon_compile() rejects the script (0 otherwise), which mayhem/raw_main.c turns into the exit
 * status, like the CLI's `exit(1)` on a syntax error. See mayhem/raw_main.c for why the target is a
 * raw file-input program and why the function is named RunOneTest.
 */
#include "lemon.h"
#include "input.h"
#include "lstring.h"
#include "lib/builtin.h"

#ifdef MODULE_OS
#include "lib/os.h"
#endif

#ifdef MODULE_SOCKET
#include "lib/socket.h"
#endif

#include <stdint.h>
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

#ifdef MODULE_OS
	lobject_set_item(lemon,
	                 lemon->l_modules,
	                 lstring_create(lemon, "os", 2),
	                 os_module(lemon));
#endif

#ifdef MODULE_SOCKET
	lobject_set_item(lemon,
	                 lemon->l_modules,
	                 lstring_create(lemon, "socket", 6),
	                 socket_module(lemon));
#endif

	/*
	 * input_set_buffer stores the pointer directly (no copy) and reads up to
	 * `size` bytes; keep a private, NUL-terminated copy alive across the
	 * compile and free it afterwards (lemon_destroy does not own it).
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

	lemon_destroy(lemon);
	free(buffer);

	return compiled ? 0 : 1;
}
