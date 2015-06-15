
#ifndef TOR_FUZZ_TORRC_H
#define TOR_FUZZ_TORRC_H

#include "fuzz_prefix.h"

int tor_fuzz_torrc_crypto_early_init_minimal(void);

int tor_fuzz_torrc_tor_init(int argc, char *argv[]);

/* From crypto.c */
extern int crypto_early_initialized_;

#endif // TOR_FUZZ_TORRC_H

