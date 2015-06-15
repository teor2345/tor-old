
#ifndef TOR_FUZZ_COMMON_H
#define TOR_FUZZ_COMMON_H

#include "fuzz_prefix.h"
#include "or.h"

int tor_fuzz_crypto_rand_zero(char *to, size_t n);

void tor_fuzz_disable_output(void);

void tor_fuzz_set_zero_time(void);

void tor_fuzz_common_setup(void);

/* From main.c */
extern int quiet_level;
extern time_t time_of_process_start;

/* From log.c */
extern int log_global_min_severity_;

#endif // TOR_FUZZ_COMMON_H

