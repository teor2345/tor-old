#!/bin/sh
# Generates asic test cases for torrc fuzzing

TESTCASE="/test/fuzz/tor/testcase"

echo "Generating basic test cases:"

mkdir -p "$TESTCASE"

echo "ORPort 1234" > "$TESTCASE"/auth_torrc
echo "AuthoritativeDirectory 1" >> "$TESTCASE"/auth_torrc
echo "V3AuthoritativeDirectory 1" >> "$TESTCASE"/auth_torrc

echo "ORPort 2345" > "$TESTCASE"/relay_torrc

echo "ORPort 3456" > "$TESTCASE"/bridge_torrc
echo "BridgeRelay 1" >> "$TESTCASE"/bridge_torrc

echo "SOCKSPort 4567" > "$TESTCASE"/client_torrc

touch "$TESTCASE"/empty_torrc
