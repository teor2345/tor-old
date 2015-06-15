#!/bin/sh
# Tell user how to launch multiple instances of
# afl_fuzz_tor_instance.sh -M/-S <id>
# in order to fuzz tor using AFL.

FUZZ_INST="/test/tor/tor-target/contrib/fuzz/fuzzer/afl/afl_fuzz_tor_instance.sh"

TESTCASE="/test/fuzz/tor-torrc/testcase"
SYNC="/test/fuzz/tor-torrc/sync"
TOKEN="/test/fuzz/tor-torrc/tokens.txt@1"

#./tor_generate_token_list.sh

#./tor_generate_basic_testcases.sh

mkdir -p "$SYNC"


echo "Now manually launch one per processor:"
echo "You may wish to startup screen first"

echo "$FUZZ_INST" "$TESTCASE" "$SYNC" "$TOKEN" -M fuzzer00m
#open "$FUZZ_INST" --args "$TESTCASE" "$SYNC" "$TOKEN" -M fuzzer00m &

echo "$FUZZ_INST" "$TESTCASE" "$SYNC" "$TOKEN" -S fuzzer01s
#open "$FUZZ_INST" --args "$TESTCASE" "$SYNC" "$TOKEN" -S fuzzer01s &

echo "$FUZZ_INST" "$TESTCASE" "$SYNC" "$TOKEN" -S fuzzer02s
#open "$FUZZ_INST" --args "$TESTCASE" "$SYNC" "$TOKEN" -S fuzzer02s &

echo "$FUZZ_INST" "$TESTCASE" "$SYNC" "$TOKEN" -S fuzzer03s
#open "$FUZZ_INST" --args "$TESTCASE" "$SYNC" "$TOKEN" -S fuzzer03s &

#echo "Finished launching multiple fuzzer instances."
