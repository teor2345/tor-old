
#include <stdio.h>
#include <string.h>

#include "fuzz_common.h"

#include "torlog.h"
#include "util.h"

/* Ordinarily defined in tor_main.c; this bit is just here to provide one
 * since we're not linking to tor_main.c */
const char tor_git_revision[] = "";

/** Write <b>n</b> bytes of zeroes to <b>to</b>.
 * This makes fuzzing runs deterministic.
 * Always returns 0 for success.
 */
int
tor_fuzz_crypto_rand_zero(char *to, size_t n)
{
  tor_assert(n < INT_MAX);
  tor_assert(to);
  memset(to, 0, n);
  return 0;
}

/** don't ever output anything
 */
void
tor_fuzz_disable_output(void)
{
  freopen("/dev/null","w",stdout);
  freopen("/dev/null","w",stderr);

  init_logging(0);
  /* Disable all logging */
  quiet_level = 2;
  log_global_min_severity_ = -1;
}

/** Make the time zero for repeatable runs
 * libfaketime might need to be used for more complex time dependencies
 */
void
tor_fuzz_set_zero_time(void)
{
  time_of_process_start = 0;
  update_approx_time(0);
}

/** Call several standard fuzzing setup functions
 */
void
tor_fuzz_common_setup(void)
{
  tor_fuzz_disable_output();
  tor_fuzz_set_zero_time();
}

