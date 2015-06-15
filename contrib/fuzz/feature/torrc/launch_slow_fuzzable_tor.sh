#!/bin/sh
# tor should probably be compiled with some or all of the following options:
# Die on errors, check for issues:
#   -DPARANOIA -D_FORTIFY_SOURCE=2 -fstack-protector-all
#   -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error -ftrapv
#   #define tor_fragile_assert() assert(0)
# Compile efficient code:
#   -Ofast -ffp-contract=fast -fslp-vectorize-aggressive -fstrict-enums
#   -funroll-loops -fstrict-aliasing -Wstrict-aliasing
# Exit early, don't hang around:
#   exit(0) if DisableNetwork is set in should_delay_dir_fetches()
#   exit(-1) if the end of should_delay_dir_fetches() is reached
# Defaults torrc set to:
#

TOR="/test/tor/tor-afl-install-x86_64/bin/tor"
export DATA_DIR=`mktemp -d -t tor_fuzz.$$`

"$TOR" --DisableNetwork 1 --ShutdownWaitLength 0 --DataDirectory "$DATA_DIR" --ORPort 12345 --PidFile "$DATA_DIR"/pid -f "$1" || echo "tor died with status $?"

# just in case: generate SIGTERM, hopefully after the torrc has been parsed
(sleep 10; kill $!) &
