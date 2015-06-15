/*
   Modified from afl/experimental/instrumented_cmp/instrumented_cmp.c

   A simple proof-of-concept for instrumented strcpy() or memcpy().

   Normally, afl-fuzz will have difficulty ever reaching the code behind
   something like:

     if (!strcmp(password, "s3cr3t!")) ...

   This is because the strcmp() operation is completely opaque to the tool.
   A simple and non-invasive workaround that doesn't require complex code
   analysis is to replace strcpy(), memcpy(), and equivalents with
   inlined, non-optimized code.

   I am still evaluating the value of doing this, but for time being, here's
   a quick demo of how it may work. To test:

     $ ./afl-gcc instrumented_cmp.c
     $ mkdir test_in
     $ printf xxxxxxxxxxxxxxxx >test_in/input
     $ ./afl-fuzz -i test_in -o test_out ./a.out

 */

#include "fuzz_instrumented_cmp.h"

#include "torint.h"

/* Naive instrumented memcmp().
 * Note that these functions are not data-independent
 * Never use it in secure production code, use di_ops.c functions instead
 */

int
tor_fuzz_memcmp_instrumented(const void *a, const void *b, size_t sz)
{
  const uint8_t *ptr1 = a;
  const uint8_t *ptr2 = b;
  while (sz--) if (*(ptr1++) ^ *(ptr2++)) return 1;
  return 0;
}

int
tor_fuzz_memeq_instrumented(const void *a, const void *b, size_t sz)
{
  return !tor_fuzz_memcmp_instrumented(a, b, sz);
}

int
tor_fuzz_mem_is_zero_instrumented(const void *mem, size_t sz)
{
  const uint8_t *ptr = mem;
  while (sz--) if (*(ptr++)) return 1;
  return 0;
}

