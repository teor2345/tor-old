
/* Modified from afl/experimental/instrumented_cmp/instrumented_cmp.c
 */

#ifndef TOR_FUZZ_INSTRUMENTED_CMP_H
#define TOR_FUZZ_INSTRUMENTED_CMP_H

#include <sys/types.h>

/* Naive instrumented memcmp().
 * Note that these functions are not data-independent
 * Never use it in secure production code, use di_ops.c functions instead
 */

int tor_fuzz_memcmp_instrumented(const void *a, const void *b, size_t sz);

int tor_fuzz_memeq_instrumented(const void *a, const void *b, size_t sz);

int tor_fuzz_mem_is_zero_instrumented(const void *mem, size_t sz);

#endif // TOR_FUZZ_INSTRUMENTED_CMP_H

