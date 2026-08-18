/*
 * mayhem/lsan_off.c -- disable ONLY LeakSanitizer, at build time, for every binary mayhem/build.sh
 * links (the two Mayhem targets lemon_compile and lemon_execute, and the lemon-oracle CLI that
 * mayhem/test.sh also runs -- all from the same sanitized objects).
 * ASan's memory-corruption checks (heap overflow, use-after-free, ...) and UBSan stay on and
 * halting; this fleet fuzzes for memory corruption, not leaks (SPEC.md §6 item 15, PORTING.md).
 *
 * lemon also has a known upstream leak that would otherwise fire on essentially every input:
 * allocator_alloc() (src/allocator.c) sends any request with (size>>3) >= ALLOCATOR_POOL_SIZE
 * straight to malloc() with no pool back-pointer, and allocator_destroy() only walks the pools,
 * so those blocks are never reclaimed -- exactly as the upstream CLI leaks them on exit.
 * lexer_scan_name() allocates a LEMON_NAME_MAX (256) byte buffer for every identifier token,
 * which lands on that path.
 */
int __lsan_is_turned_off(void) { return 1; }
