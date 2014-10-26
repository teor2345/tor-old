
/** Xcode expects architecture-specific code to be conditionalised,
 * rather than being in different files. It doesn't have per-architecture 
 * file -> target memberships, so we fake it here. */

/* define USE_CURVE25519_DONNA_C64 to 0 to avoid using c64 code on x86_64 */
#ifndef USE_CURVE25519_DONNA_C64
#define USE_CURVE25519_DONNA_C64 1
#endif

#if defined(__x86_64__) && USE_CURVE25519_DONNA_C64
#include "../../src/ext/curve25519_donna/curve25519-donna-c64.c"
#else /* __i386__ || !USE_CURVE25519_DONNA_C64 */
#include "../../src/ext/curve25519_donna/curve25519-donna.c"
#endif /* __x86_64__ && USE_CURVE25519_DONNA_C64 */
