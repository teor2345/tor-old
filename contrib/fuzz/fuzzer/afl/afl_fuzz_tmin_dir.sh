#!/bin/bash
AFL_TMIN="/test/fuzz/afl-install/bin/afl-tmin"
CASE_DIR="test-cmin"
MIN_DIR="test-tmin"
TOR_FUZZER="/test/tor/tor-target/src/test/fuzz-torrc --verify-config -f @@"
# Tor parsing misbehaves badly on inputs ending in backslash-newline
TIMEOUT_MS=35000
# to run parallel instances, replace * with [0-1]* or [a-d]* etc.
for fname in "$CASE_DIR"/*; do newname="$MIN_DIR"/`basename "$fname"`; if [ -f "$newname" ]; then echo "File $fname already minimised"; continue; fi; AFL_DEFER_FORKSRV=1 "$AFL_TMIN" -i "$fname" -o "$newname" -t "$TIMEOUT_MS" $TOR_FUZZER; done;
