
#ifndef TOR_FUZZER_H
#define TOR_FUZZER_H

#include "fuzz_prefix.h"

/* This header contains the common functions supported by each fuzzer
 * It acts as the header for fuzzers without their own functions,
 * including fuzzer_stub.c
 */

/* Please this function after standard initialisation code,
 * but before any data-specific code
 */
void tor_fuzzer_manual_init(void);

#endif // TOR_FUZZER_H

