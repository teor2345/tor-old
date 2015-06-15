
/* This file contains the afl-specific implementations of
 * common fuzzer functions, and any afl-specific functions
 */

#include "fuzzer_afl.h"

#ifdef __AFL_HAVE_MANUAL_INIT
void __afl_manual_init(void);
#endif

/* Initialise the AFL fuzzer
 * This has no effect with afl-clang, only afl-clang-fast
 * "be sure to set AFL_DEFER_FORKSRV=1 before invoking afl-fuzz"
 * See afl/llvm_mode/README.llvm
 */
void
tor_fuzzer_manual_init()
{
#ifdef __AFL_HAVE_MANUAL_INIT
  __afl_manual_init();
#endif
}

