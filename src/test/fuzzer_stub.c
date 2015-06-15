
/* This file contains the afl-specific implementations of common functions,
 * and any afl-specific functions
 */

#include "fuzzer_afl.h"

#ifdef __AFL_HAVE_MANUAL_INIT
void __afl_manual_init(void);
#endif

int tor_fuzzer_manual_init() {
#ifdef __AFL_HAVE_MANUAL_INIT
  __afl_manual_init();
#endif
}
