= Fuzzing Tor

To run the fuzzing test cases in a deterministic fashion, use:
  make fuzz

== Guided Fuzzing with AFL

There is no HTTPS, hash, or signature for American Fuzzy Lop's source code, so
its integrity can't be verified. That said, you really shouldn't fuzz on a
machine you care about, anyway.

To Build:
  Get AFL from http://lcamtuf.coredump.cx/afl/ and unpack it
  cd afl
  make
  cd ../tor
  PATH=$PATH:../afl/ CC="../afl/afl-gcc" ./configure --enable-expensive-hardening
  AFL_HARDEN=1 make clean fuzz

To Run:
  mkdir -p src/test/fuzz/fuzz_dir_findings
  ../afl/afl-fuzz -i src/test/fuzz/fuzz_dir_testcase -o src/test/fuzz/fuzz_dir_findings -x src/test/fuzz/fuzz_dir_http_header.dct -- src/test/fuzz_dir

AFL has a multi-core mode, check the documentation for details.

OS X requires slightly more preparation, including:
* using afl-clang (or afl-clang-fast from the llvm directory)
* disabling external crash reporting (AFL will guide you through this step)

AFL may also benefit from using dictionary files for text-based inputs: a
dictionary containing the tor directory protocol HTTP header tokens is
available at fuzz_dir_http_header.dct.

Multiple dictionaries can be used with AFL, you should choose a combination of
dictionaries that targets the code you are fuzzing.

== Writing Tor fuzzers

A tor fuzzing harness should:
* read input from standard input (many fuzzing frameworks also accept file
  names)
* parse that input
* produce results on standard output (this assists in diagnosing errors)

Most fuzzing frameworks will produce many invalid inputs - a tor fuzzing
harness should rejecting invalid inputs without crashing or behaving badly.

But the fuzzing harness should crash if tor fails an assertion, triggers a
bug, or accesses memory it shouldn't. This helps fuzzing frameworks detect
"interesting" cases.

== Reporting Issues

Please report any issues discovered using the process in Tor's security issue
policy:

https://trac.torproject.org/projects/tor/wiki/org/meetings/2016SummerDevMeeting/Notes/SecurityIssuePolicy

