/*
 * mayhem/raw_main.c -- main() of the two RAW file-input Mayhem targets (/mayhem/lemon_compile for
 * target `lemon`, /mayhem/lemon_execute for target `lemon_execute`; see mayhem/build.sh).
 *
 * `<binary> <file>`: read the whole input file (the Mayhemfile's `@@`) into memory and hand it to
 * the per-input entry point RunOneTest() of the target it is linked with -- mayhem/fuzz_compile.c
 * (Lemon front end only) or mayhem/fuzz_execute.c (front end + bytecode VM). One process per input:
 * a crash anywhere in Lemon is the process's own crash (ASan/UBSan abort), a hang is bounded only by
 * the Mayhemfile's per-test `timeout:` (no timer, alarm or signal handler here or anywhere under
 * mayhem/, issue #1298).
 *
 * Exit status: RunOneTest()'s result -- 0 when Lemon accepted (compiled) the script, 1 when Lemon
 * rejected it (lemon_compile() failed; Lemon has already printed its diagnostic), the same
 * convention as the upstream `lemon` CLI (src/main.c). 2 = the input file could not be read.
 *
 * Why this is not a libFuzzer binary any more (issue #1313): these targets are fuzzed one process
 * per input because Lemon has real, shallow crashes (a 1-byte `-` or `!` overflows the parser's
 * stack; `var ;` NULL-derefs in compiler.c) and both targets' accumulated server-side corpora hold
 * such inputs; an in-process libFuzzer run aborts while loading that corpus (Mayhem: "libFuzzer
 * target failed to fuzz for 5 iterations"). The file-input program therefore carries its own
 * main() and no libFuzzer entry point, and is built with -fsanitize=fuzzer-no-link so Mayhem still
 * reads SanitizerCoverage edges from it.
 *
 * Why the per-input function is named RunOneTest: it is the one frame that is live exactly while
 * Lemon processes the input. rlenv's premature-exit check (rlenv-mcp premature_exit.py,
 * CALLBACK_SENTINELS) treats a SUCCESS exit taken while such a frame is still on the stack as a
 * masked crash -- that is what catches a "fix" that calls exit(0)/_exit(0) on the crashing path
 * instead of fixing it. A genuine run always returns from RunOneTest() before main() returns, so
 * the name changes nothing for an honest patch; it keeps the same protection the old
 * libFuzzer-shaped standalone binaries had.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int RunOneTest(const uint8_t *data, size_t size);

int
main(int argc, char *argv[])
{
	FILE *fp;
	uint8_t *data = NULL;
	size_t size = 0, cap = 0, n;
	int status;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
		return 2;
	}
	fp = fopen(argv[1], "rb");
	if (!fp) {
		perror(argv[1]);
		return 2;
	}
	/* Read to EOF (no seek), so any readable path works, including a pipe. */
	for (;;) {
		if (size == cap) {
			uint8_t *grown;

			cap = cap ? cap * 2 : 4096;
			grown = realloc(data, cap);
			if (!grown) {
				perror("realloc");
				free(data);
				fclose(fp);
				return 2;
			}
			data = grown;
		}
		n = fread(data + size, 1, cap - size, fp);
		size += n;
		if (n == 0) {
			break;
		}
	}
	if (ferror(fp)) {
		perror(argv[1]);
		free(data);
		fclose(fp);
		return 2;
	}
	fclose(fp);

	status = RunOneTest(data, size);
	free(data);

	return status;
}
