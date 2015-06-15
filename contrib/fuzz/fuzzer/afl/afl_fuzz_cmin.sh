#!/bin/bash
AFL_CMIN="/test/fuzz/afl-install/bin/afl-cmin"
CASE_DIR="previous"
MIN_DIR="previous-min"
TOR_FUZZER="/test/tor/tor-target/src/test/fuzz-torrc --verify-config -f @@"
# Tor parsing misbehaves badly on inputs ending in backslash-newline
TIMEOUT_MS=5000
AFL_DEFER_FORKSRV=1 "$AFL_CMIN" -i "$CASE_DIR" -o "$MIN_DIR" -t "$TIMEOUT_MS" $TOR_FUZZER
