
/* we want access to various implementation details */
#ifndef TOR_UNIT_TESTS
#define TOR_UNIT_TESTS
#endif
#include "testsupport.h"
#include "or.h"

#include "fuzz-torrc.h"
#include "fuzz_common.h"
#ifdef TOR_FUZZER_INSTRUMENTED
#include "fuzz_instrumented_cmp.h"
#endif
#include "fuzzer.h"

#include "config.h"
#include "crypto.h"
#include "util.h"

#ifndef TOR_FUZZER_ALWAYS_READ_FROM_STDIN
#define TOR_FUZZER_ALWAYS_READ_FROM_STDIN 0
#endif

/** Minimally initialize the crypto library - crypto_init_siphash_key() only.
 *  Return 0 on success, -1 on failure.
 */
int
tor_fuzz_torrc_crypto_early_init_minimal(void)
{
  if (!crypto_early_initialized_) {
    crypto_early_initialized_ = 1;
    if (crypto_init_siphash_key() < 0)
      return -1;
  }
  return 0;
}

/** Main entry point for the Tor command-line client.
 */
int
tor_fuzz_torrc_tor_init(int argc, char *argv[])
{
#if TOR_FUZZER_ALWAYS_READ_FROM_STDIN
  if (argc <= 1) {
    char *argv0 = argc > 0 ? argv[0] : NULL;
    argc = 4;
    /* we "leak" the actual command-lines arguments and argv itself here
     * is this ok because they are system-allocated? */
    argv = (char **)tor_calloc_(argc, sizeof(char *));
    /* verify a config supplied through the standard input */
    argv[0] = argv0;
    argv[1] = tor_strdup_("--verify-config");
    argv[2] = tor_strdup_("-f");
    argv[3] = tor_strdup_("-");
    /* argv[4] = tor_strdup_("--quiet"); */
  }
#endif

  /* Set up the crypto nice and early */
  if (tor_fuzz_torrc_crypto_early_init_minimal() < 0) {
    /* log_err(LD_GENERAL, "Unable to initialize the crypto subsystem!"); */
    return 1;
  }

  tor_fuzzer_manual_init();

  if (options_init_from_torrc(argc,argv) < 0) {
    /* log_err(LD_CONFIG,"Reading config failed--see warnings above."); */
    return -1;
  }

  return 0;
}

int
main(int argc, char *argv[])
{
  /* Replace functions required by this fuzzing harness */
  MOCK(crypto_rand, tor_fuzz_crypto_rand_zero);

  /* Replace functions with instrumented versions for afl-fuzz and similar */
#ifdef TOR_FUZZER_INSTRUMENTED
  MOCK(tor_memcmp, tor_fuzz_memcmp_instrumented);
  MOCK(tor_memeq, tor_fuzz_memeq_instrumented);
  MOCK(safe_mem_is_zero, tor_fuzz_mem_is_zero_instrumented);
#endif

  tor_fuzz_common_setup();

#if !TOR_FUZZER_ALWAYS_READ_FROM_STDIN
  if (argc < 4)
    fprintf(stderr, "Usage: %s --verify-config -f @@\n"
            "Where @@ is the fuzzer-supplied torrc filename.\n",
            argv[0] ? argv[0] : NULL);
#endif

  if (tor_fuzz_torrc_tor_init(argc, argv)<0)
    return -1;

  /* don't bother with tor_cleanup() or UNMOCK() */

  return 0;
}

