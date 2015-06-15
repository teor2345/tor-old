#!/bin/sh
# Launch a single afl-fuzz instance

export AFL_DEFER_FORKSRV=1
# Don't know why tor's execution is non-deterministic,
# but don't bother to check
export AFL_NO_VAR_CHECK=1

AFL_FUZZ="/test/fuzz/afl-install/bin/afl-fuzz"
TOR_FUZZ="/test/tor/tor-target/src/test/fuzz-torrc --verify-config -f @@"
TESTCASE="$1"
SYNC="$2"
TOKEN="$3"

# Do a basic setup in case we are called on our own
mkdir -p "$TESTCASE"
mkdir -p "$SYNC"

#echo "ContactInfo hello world" > $TESTCASE/hello_torrc

#sudo echo "Activating sudo"

# Could use -m 50, but tor doesn't seem to use that much,
# and we're running with ASAN, so -m doesn't work well
# Use -t 1000+ as the initial cases include a network timeout on OS X
echo AFL_DEFER_FORKSRV=1 AFL_NO_VAR_CHECK=1 "$AFL_FUZZ" -i "$TESTCASE" -o "$SYNC" -x "$TOKEN" -t 1000+ "$4" "$5" $TOR_FUZZ
"$AFL_FUZZ" -i "$TESTCASE" -o "$SYNC" -x "$TOKEN" -t 1000+ "$4" "$5" $TOR_FUZZ &
#sudo renice -20 $!
