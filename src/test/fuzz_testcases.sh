#!/bin/sh

set -e

if [ $# -le 1 ] || [ ! -d "${1}" ] || [ ! -d "${2}" ]; then
  if [ "$FUZZ_BINARY_DIR" = "" -o "$fuzz_testcase_dir" = "" ] ; then
    echo "Usage: ${0} PATH_TO_FUZZ_BINARY_DIR PATH_TO_FUZZ_TESTCASE_DIR \
[names_of_fuzz_binaries]"
    exit 1
  fi
fi

if [ $# -ge 1 ]; then
  FUZZ_BINARY_DIR="${1}"
  shift
fi

if [ $# -ge 1 ]; then
  fuzz_testcase_dir="${1}"
  shift
fi

if [ $# -ge 1 ]; then
  FUZZ_BINARY_NAMES="${@}"
fi

# now, execute every fuzzer with every relevant testcase
# this will fail if fuzzer names have spaces in them, so don't do that
for fuzzer in $FUZZ_BINARY_NAMES ; do
  echo "Running tests for $fuzzer:"
  # search for test cases ending in .txt or .bin
  for testcase in "$fuzz_testcase_dir/${fuzzer}_testcase"/*.txt "$fuzz_testcase_dir/${fuzzer}_testcase"/*.bin ; do
    echo "Running $testcase for $FUZZ_BINARY_DIR/$fuzzer:"
    "$FUZZ_BINARY_DIR/$fuzzer" < "$testcase"
  done
done
