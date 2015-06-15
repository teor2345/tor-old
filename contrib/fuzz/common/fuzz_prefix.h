
/* This needs to be used as a prefix header for all of tor during fuzzing
 * ./configure CPPFLAGS="-include src/test/fuzz_prefix.h"
 * If you change this header, make may not pick it up. Use "make clean".
 */

#ifndef TOR_FUZZ_PREFIX_H
#define TOR_FUZZ_PREFIX_H

/* we want access to various implementation details */
#ifndef TOR_UNIT_TESTS
#define TOR_UNIT_TESTS
#endif

/* Does the fuzzer benefit from instrumented_cmp.c and similar? */
#ifndef TOR_FUZZER_INSTRUMENTED
#define TOR_FUZZER_INSTRUMENTED
#endif

/* We want to instrument all memcmp functions */
#ifdef TOR_FUZZER_INSTRUMENTED
#ifndef fast_memcmp
#define fast_memcmp        tor_memcmp
#endif

#ifndef fast_memeq
#define fast_memeq         tor_memeq
#endif

#ifndef fast_memneq
#define fast_memneq        tor_memneq
#endif
#endif

/** Define this if you want Tor to crash when any problem comes up,
 * so you can get a coredump and track things down.
 */
#ifndef tor_fragile_assert
#define tor_fragile_assert() tor_assert(0)
#endif

#endif // TOR_FUZZ_PREFIX_H

