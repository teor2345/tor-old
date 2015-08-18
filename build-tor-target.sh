#!/bin/bash

# Produce multiple tor builds from the same (C) source directory
# Each build has a varying level of security:
#   features: enable features, disable security
#   default: default configuration
#   performance: fastest configuration
#   afl: configuration designed for use with afl-fuzz
#   harden: disable features, enable extra security
# This assists in determining vulnerable features during testing

# Run this script in a directory containing the tor source distribution

CLANG="clang"
#CLANG="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
CLANG_AFL="/test/fuzz/afl-install/bin/afl-clang"
CLANG_AFL_FAST="/test/fuzz/afl-install/bin/afl-clang-fast"
export AFL_PATH="/test/fuzz/afl-install/lib/afl/"
export AFL_HARDEN=1

./autogen.sh || exit 1

ASCIIDOC="--disable-asciidoc" #""
ARCHS="x86_64 i386"
CHUTNEY_FLAVOUR="bridges+ipv6+hs" # "basic-min"

PREFIX_BASE=/test/tor
EXT_DIR=/test/tor/external
EXT_INCDIR=/test/tor/external/include
EXT_LIBDIR=/test/tor/external/lib
LIBEVENT_LATEST_DIR=/test/tor/libevent-install
ZLIB_LATEST_DIR=/test/tor/zlib-install
OPENSSL_LATEST_DIR=/test/tor/openssl-install
LIBRESSL_DIR=/test/tor/libressl-install
# BoringSSL doesn't install, and doesn't build dynamic libraries by default
BORINGSSL_DIR=/test/tor/boringssl-install

CLANG_BACKTRACE="-fno-omit-frame-pointer -fasynchronous-unwind-tables -fno-optimize-sibling-calls -fno-inline"
CLANG_PROTECT="-DPARANOIA -fstack-protector-all"
CLANG_SAN_BLACKLIST="-fsanitize-blacklist=contrib/clang/sanitize_blacklist.txt"
CLANG_SAN="-fsanitize=undefined -fno-sanitize-recover=all $CLANG_SAN_BLACKLIST $CLANG_BACKTRACE"
CLANG_SAN_TRAP="-ftrapv -fsanitize-undefined-trap-on-error $CLANG_SAN_BLACKLIST"
CLANG_SAN_ADDRESS="-fsanitize=address $CLANG_SAN_BLACKLIST $CLANG_BACKTRACE"
CLANG_SAN_ADDRESS_LDFLAGS="-fsanitize=address $CLANG_BACKTRACE $CLANG_SAN_BLACKLIST"
CLANG_UNSAN="-fwrapv"
CLANG_DEBUG="-g $CLANG_BACKTRACE"

# This really doesn't work that well, and neither does -emit-llvm
# It causes type assertion failures - maybe a bug fixed in a later version?
FLTO_CFLAGS="" #"-flto -emit-llvm"
FLTO_LDFLAGS="" #"-flto"

DCE_CFLAGS="" # -fdce doesn't work
DCE_LDFLAGS="" # I can't seem to get -dead-strip to work either

O_MAX="-Ofast -ffast-math -ffp-contract=fast -fslp-vectorize-aggressive -momit-leaf-frame-pointer -mrelax-all -fstrict-aliasing -Wstrict-aliasing $DCE_CFLAGS"
O_FAST="-O2 -funroll-loops -ffp-contract=on -fno-omit-frame-pointer -mrelax-all -fstrict-aliasing -Wstrict-aliasing $DCE_CFLAGS"
O_SIZE="-Oz -fno-omit-frame-pointer $DCE_CFLAGS"
O_MIN="-O1 $DCE_CFLAGS"
O_NONE="-O0 $DCE_CFLAGS"

# to aid debugging
#FLTO_CFLAGS=""
#FLTO_LDFLAGS=""
#O_DCE="" #"-dead-strip" # -fdce doesn't work
#O_FAST=$O_NONE
#O_SIZE=$O_NONE
#O_MIN=$O_NONE

# dmalloc doesn't seem to work on the latest builds without -DFINI_DMALLOC=1,
# which is difficult to configure.
# We might use the system guard malloc instead.

CPPFLAGS_BASE="-I$EXT_INCDIR"
LDFLAGS_BASE="$CLANG_PROTECT" #"-L$EXT_LIBDIR"
LDFLAGS_STATIC="-L$EXT_LIBDIR $CLANG_PROTECT"

# we can also use --analyze for the clang static analyser
# -ftrapv causes the sscanf test to crash / fail
# as do -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error
# -fbounds-checking causes lots of incorrect deprecation warnings
# -fsanitize-memory-track-origins increases memory usage, and causes warnings
# PARANOIA activates extra asserts
# _FORTIFY_SOURCE is defined by configure --enable-gcc-hardening
# Ideally, we don't want to use -Wall or -Wextra,
#   so we can use -Werror with tor-specific warning flags and build clean
# We have used -advisory in the past,
#   as some system header macros trigger -Wshorten-64-to-32
# Trap instructions generated using __builtin_trap() stomp the stack
#   we could use abort() instead, but it doesn't seem to work:
#  -ftrap-function=abort
CLANG_COVERAGE="-fprofile-arcs -ftest-coverage"

# This saves time, but produces bugs when manually developing and retesting
# --disable-dependency-tracking
CONFIG_OPTS=""
CONFIG_OPTS_COVERAGE="--enable-coverage"

OPENSSL_EXT="--with-openssl-dir=$EXT_LIBDIR"
CPPFLAGS_OPENSSL_EXT="" #"-I$OPENSSL_EXT_DIR/include"
LDFLAGS_OPENSSL_EXT="" #"-L$OPENSSL_EXT_DIR/lib"
LDFLAGS_OPENSSL_EXT_STATIC="-L$OPENSSL_EXT_DIR/lib"

LIBRESSL="--with-openssl-dir=$LIBRESSL_DIR"
CPPFLAGS_LIBRESSL="-I$LIBRESSL_DIR/include"
LDFLAGS_LIBRESSL="" #"-L$LIBRESSL_DIR/lib"
LDFLAGS_LIBRESSL_STATIC="-L$LIBRESSL_DIR/lib"

# BoringSSL doesn't build dynamic libraries by default, or very easily
BORINGSSL="--enable-static-openssl --with-openssl-dir=$BORINGSSL_DIR"
CPPFLAGS_BORINGSSL="-I$BORINGSSL_DIR/include"
LDFLAGS_BORINGSSL="-L$BORINGSSL_DIR/lib"
LDFLAGS_BORINGSSL_STATIC="$LDFLAGS_BORINGSSL"

MAKE="make -j6"

if [ ! -z "$2" ]; then
ARCHS="$2"
fi

if [ ! -z "$3" ]; then
CHUTNEY_FLAVOUR="$3"
fi

date

# If any of these builds fail, we want to stop there and fix the error

if [ "$1" = "features" -o -z "$1" ]; then

# Enable extras, disable security, use (older) system libraries
# We could also use libnatpmp if available: --enable-nat-pmp
# $CLANG_COVERAGE
CC="$CLANG $CLANG_DEBUG $CLANG_PROTECT $CLANG_SAN $CLANG_SAN_ADDRESS $O_NONE"

#$MAKE reset-gcov \
#&& lcov --rc lcov_branch_coverage=1 --directory ./src --zerocounters \

for ARCH in $ARCHS; do
echo "tor-features $ARCH"

# OPENSSL_LATEST uses the architecture in the linker paths
OPENSSL_LATEST="--with-openssl-dir=${OPENSSL_LATEST_DIR}-$ARCH"
CPPFLAGS_OPENSSL_LATEST="-I${OPENSSL_LATEST_DIR}-$ARCH/include -DOPENSSL_USE_DEPRECATED" # -DOPENSSL_NO_DEPRECATED
LDFLAGS_OPENSSL_LATEST="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"
LDFLAGS_OPENSSL_LATEST_STATIC="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"

#OPENSSL="$OPENSSL_EXT"
#CPPFLAGS="$CPPFLAGS_OPENSSL_EXT $CPPFLAGS_BASE"
#LDFLAGS="$CLANG_SAN $CLANG_SAN_ADDRESS $LDFLAGS_OPENSSL_EXT $LDFLAGS_BASE $FLTO_LDFLAGS" # _STATIC

OPENSSL="$OPENSSL_LATEST"
CPPFLAGS="$CPPFLAGS_OPENSSL_LATEST $CPPFLAGS_BASE"
LDFLAGS="$CLANG_SAN $CLANG_SAN_ADDRESS $LDFLAGS_OPENSSL_LATEST $LDFLAGS_BASE $FLTO_LDFLAGS" # _STATIC

#export PATH=$LIBRESSL_DIR/bin:$PATH
#OPENSSL="$LIBRESSL"
#CPPFLAGS="$CPPFLAGS_LIBRESSL $CPPFLAGS_BASE"
#LDFLAGS="$CLANG_SAN $CLANG_SAN_ADDRESS $LDFLAGS_LIBRESSL $LDFLAGS_BASE $FLTO_LDFLAGS" # _STATIC

#export PATH=$BORINGSSL_DIR/bin:$PATH
#OPENSSL="$BORINGSSL"
#CPPFLAGS="$CPPFLAGS_BORINGSSL $CPPFLAGS_BASE"
#LDFLAGS="$CLANG_SAN $CLANG_SAN_ADDRESS $LDFLAGS_BORINGSSL $LDFLAGS_BASE $FLTO_LDFLAGS" # _STATIC

LIBEVENT="--with-libevent-dir=$EXT_LIBDIR"

$MAKE clean \
&& echo ./configure --prefix=$PREFIX_BASE/tor-features-install-$ARCH \
  CC="$CC -arch $ARCH" CPPFLAGS="$CPPFLAGS" CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS $ASCIIDOC \
  --enable-upnp --with-libminiupnpc-dir=$EXT_LIBDIR \
  --enable-instrument-downloads \
  --disable-gcc-hardening --disable-linker-hardening --enable-gcc-warnings \
&& ./configure --prefix=$PREFIX_BASE/tor-features-install-$ARCH \
  CC="$CC -arch $ARCH" CPPFLAGS="$CPPFLAGS" CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS $ASCIIDOC \
  --enable-upnp --with-libminiupnpc-dir=$EXT_LIBDIR \
  --enable-instrument-downloads \
  --disable-gcc-hardening --disable-linker-hardening --enable-gcc-warnings \
&& $MAKE \
&& date || exit 11

# Allow address sanitizer to work with the tests
ASAN_OPTIONS=allow_user_segv_handler=1 $MAKE check \
&& src/test/bench \
&& date || exit 12
# src/test/bench only adds 9 functions

# exit before installing this variant, or compliling other variants
# exit

#/usr/libexec/ApplicationFirewall/socketfilterfw --add /test/tor-target/src/or/tor
$CHUTNEY_PATH/tools/kill-all-nodes.sh
# work around an issue where make test-network hangs on -j2
# also work around an issue where consensus-building occasionally fails
# the other tests are redundant when we're running bridges+ipv6
#make -j1 test-network \
#  || make -j1 test-network \
#&& src/test/test-network.sh --flavour bridges \
#  || src/test/test-network.sh --flavour bridges \
src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR \
  || src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR --sleep 60 \
  || src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR --sleep 300 \
&& date || exit 13
$CHUTNEY_PATH/tools/kill-current-nodes.sh

# exit after coverage but before install
#break?

$MAKE install \
&& date || exit 14

done # for ARCH in $ARCHS;

#HTML_COVER_DIR="coverage_html_features"
#mkdir -p "$HTML_COVER_DIR" \
#&& lcov --capture --rc lcov_branch_coverage=1 --no-external --directory . \
#  --output-file "$HTML_COVER_DIR/lcov.tmp" \
#&& lcov --remove "$HTML_COVER_DIR/lcov.tmp" --rc lcov_branch_coverage=1 \
#  'test/*' 'ext/tinytest*' '/usr/*' \
#  --output-file "$HTML_COVER_DIR/lcov.info" \
#&& date || exit 15

#ERROR: required module GD.pm not found on this system (see www.cpan.org).
#&& genhtml --branch-coverage --show-details --frames -o "$HTML_COVER_DIR" \
#  "$HTML_COVER_DIR/lcov.info" \

make check-spaces || exit 16

fi # features

if [ "$1" = "default" -o -z "$1" ]; then

# Use defaults wherever possible, including (older) system libraries
# This is a little faster than the performance build for chutney capacity tests
CC="$CLANG $O_SIZE"
OPENSSL="$OPENSSL_EXT"
CPPFLAGS="$CPPFLAGS_OPENSSL_EXT $CPPFLAGS_BASE"
LDFLAGS="$LDFLAGS_OPENSSL_EXT $LDFLAGS_BASE $FLTO_LDFLAGS $DCE_LDFLAGS"

LIBEVENT="--with-libevent-dir=$EXT_LIBDIR"

for ARCH in $ARCHS; do
echo "tor-default $ARCH"
$MAKE clean \
&& echo ./configure --prefix=$PREFIX_BASE/tor-default-install-$ARCH \
  CC="$CC -arch $ARCH" CPPFLAGS="$CPPFLAGS" CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS \
  $ASCIIDOC --enable-gcc-warnings --disable-gcc-hardening \
&& ./configure --prefix=$PREFIX_BASE/tor-default-install-$ARCH \
  CC="$CC -arch $ARCH" CPPFLAGS="$CPPFLAGS" CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS \
  $ASCIIDOC --enable-gcc-warnings --disable-gcc-hardening \
&& $MAKE \
&& date || exit 21

# exit before testing/benching this variant, or compliling other variants
#break?

$MAKE check \
&& date || exit 22
#&& src/test/bench \ # only adds 9 functions

# exit before installing this variant, or compliling other variants
# break?

#/usr/libexec/ApplicationFirewall/socketfilterfw --add /test/tor-target/src/or/tor
$CHUTNEY_PATH/tools/kill-all-nodes.sh
# work around an issue where make test-network hangs on -j2
# also work around an issue where consensus-building occasionally fails
# the other tests are redundant when we're running bridges+ipv6
#make -j1 test-network \
#  || make -j1 test-network \
#&& src/test/test-network.sh --flavour bridges \
#  || src/test/test-network.sh --flavour bridges \
src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR \
  || src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR --sleep 60 \
  || src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR --sleep 300 \
&& date || exit 23
$CHUTNEY_PATH/tools/kill-current-nodes.sh

$MAKE install \
&& date || exit 24

done # for ARCH in $ARCHS;

make check-spaces || exit 26

fi # default

if [ "$1" = "performance" -o -z "$1" ]; then

# Disable extras, disable security, use latest libraries, optimise
# This is a little slower than the performance build for chutney capacity tests
CC="$CLANG $O_FAST"

# Also disable i386, it's terribly slow
for ARCH in "x86_64"; do
echo "tor-performance $ARCH"

# OPENSSL_LATEST uses the architecture in the linker paths
OPENSSL_LATEST="--with-openssl-dir=${OPENSSL_LATEST_DIR}-$ARCH"
CPPFLAGS_OPENSSL_LATEST="-I${OPENSSL_LATEST_DIR}-$ARCH/include -DOPENSSL_NO_DEPRECATED" # -DOPENSSL_USE_DEPRECATED
LDFLAGS_OPENSSL_LATEST="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"
LDFLAGS_OPENSSL_LATEST_STATIC="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"

OPENSSL="$OPENSSL_LATEST"
CPPFLAGS="$CPPFLAGS_OPENSSL_LATEST $CPPFLAGS_BASE"
LDFLAGS="$LDFLAGS_OPENSSL_LATEST $LDFLAGS_BASE $FLTO_LDFLAGS $DCE_LDFLAGS"

LIBEVENT="--with-libevent-dir=$EXT_LIBDIR"

$MAKE clean \
&& echo ./configure --prefix=$PREFIX_BASE/tor-performance-install-$ARCH \
  CC="$CC -arch $ARCH" CPPFLAGS="$CPPFLAGS" CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS $ASCIIDOC \
  --disable-transparent --disable-largefile \
  --disable-gcc-hardening --disable-linker-hardening --enable-gcc-warnings \
&& ./configure --prefix=$PREFIX_BASE/tor-performance-install-$ARCH \
  CC="$CC -arch $ARCH" CPPFLAGS="$CPPFLAGS" CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS $ASCIIDOC \
  --disable-transparent --disable-largefile \
  --disable-gcc-hardening --disable-linker-hardening --enable-gcc-warnings \
&& $MAKE \
&& date || exit 41

# exit before testing/benching this variant, or compliling other variants
#break?

# bench is important for performance tests
$MAKE check \
&& src/test/bench \
&& date || exit 42

# exit before installing this variant, or compliling other variants
# exit

#/usr/libexec/ApplicationFirewall/socketfilterfw --add /test/tor-target/src/or/tor
$CHUTNEY_PATH/tools/kill-all-nodes.sh
# work around an issue where make test-network hangs on -j2
# also work around an issue where consensus-building occasionally fails
# the other tests are redundant when we're running bridges+ipv6
#make -j1 test-network \
#  || make -j1 test-network \
#&& src/test/test-network.sh --flavour bridges \
#  || src/test/test-network.sh --flavour bridges \
src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR \
|| src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR --sleep 60 \
|| src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR --sleep 300 \
&& date || exit 43
$CHUTNEY_PATH/tools/kill-current-nodes.sh

$MAKE install \
&& date || exit 44

done # for ARCH in $ARCHS;

make check-spaces || exit 45

fi # performance

if [ "$1" = "afl" -o -z "$1" ]; then
if [ -f "src/test/fuzz_prefix.h" ]; then

# Disable extras, enable security/extra checks, use newer libraries
# Don't run anything outside of afl
# Don't use ccache, as it doesn't understand afl's asssembly insertion
export CCACHE_DISABLE=1

#export AFL_INST_RATIO=1
#export AFL_DONT_OPTIMIZE=1
#export AFL_KEEP_ASSEMBLY=1
#mkdir -p afl_assembly
#export TMPDIR=$PWD/afl_assembly
# We could also use $CLANG_SAN $CLANG_SAN_ADDRESS here, probably with crash exploration mode
# For debugging, but not fast cases: $O_NONE $CLANG_DEBUG

# You can enable one of these:
# But they're very slow on OS X: 1000 tests per second to 5 per second
#export AFL_USE_ASAN=1
#export AFL_USE_MSAN=1
# As long as you also add:
# LDFLAGS="$CLANG_SAN_ADDRESS_LDFLAGS"
CC="$CLANG_AFL $CLANG_PROTECT $CLANG_SAN_TRAP"

# i386 doesn't work with afl
ARCH="x86_64"
echo "tor-afl $ARCH"

# OPENSSL_LATEST uses the architecture in the linker paths
OPENSSL_LATEST="--with-openssl-dir=${OPENSSL_LATEST_DIR}-$ARCH"
CPPFLAGS_OPENSSL_LATEST="-I${OPENSSL_LATEST_DIR}-$ARCH/include -DOPENSSL_NO_DEPRECATED" # -DOPENSSL_USE_DEPRECATED
LDFLAGS_OPENSSL_LATEST="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"
LDFLAGS_OPENSSL_LATEST_STATIC="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"

OPENSSL="$OPENSSL_LATEST"
CPPFLAGS="$CPPFLAGS_OPENSSL_LATEST $CPPFLAGS_BASE"
LDFLAGS="$LDFLAGS_OPENSSL_LATEST_STATIC $LDFLAGS_BASE $DCE_LDFLAGS" # $CLANG_SAN_ADDRESS_LDFLAGS

LIBEVENT="--with-libevent-dir=$EXT_LIBDIR"

$MAKE clean \
&& echo ./configure --prefix=$PREFIX_BASE/tor-afl-install-$ARCH \
  CC="$CC -arch $ARCH" \
  CPPFLAGS="$CPPFLAGS -include src/test/fuzz_prefix.h" \
  CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS $ASCIIDOC \
  --with-zlib-dir=$EXT_LIBDIR \
  --enable-static-libevent --enable-static-openssl --enable-static-zlib \
  --disable-transparent --disable-largefile --disable-libscrypt \
  --disable-gcc-hardening --enable-gcc-warnings-advisory \
  --enable-unittests \
&& ./configure --prefix=$PREFIX_BASE/tor-afl-install-$ARCH \
  CC="$CC -arch $ARCH" \
  CPPFLAGS="$CPPFLAGS -include src/test/fuzz_prefix.h" \
  CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS $CLANG_SAN_ADDRESS_LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS $ASCIIDOC \
  --with-zlib-dir=$EXT_LIBDIR \
  --enable-static-libevent --enable-static-openssl --enable-static-zlib \
  --disable-transparent --disable-largefile --disable-libscrypt \
  --disable-gcc-hardening --enable-gcc-warnings-advisory \
  --enable-unittests \
&& $MAKE \
&& date || exit 51

$MAKE install \
&& date || exit 54

make check-spaces || exit 55

unset CCACHE_DISABLE

fi # src/test/fuzz_prefix.h
fi # afl

if [ "$1" = "afl-fast" -o -z "$1" ]; then
if [ -f "src/test/fuzz_prefix.h" ]; then

# Disable extras, enable security/extra checks, use newer libraries
# Don't run anything outside of afl
# Don't use ccache, as it doesn't understand afl's asssembly insertion
export CCACHE_DISABLE=1

#export AFL_INST_RATIO=1
#export AFL_DONT_OPTIMIZE=1
#export AFL_KEEP_ASSEMBLY=1
#mkdir -p afl_assembly
#export TMPDIR=$PWD/afl_assembly
# We could also use $CLANG_SAN $CLANG_SAN_ADDRESS here, probably with crash exploration mode
# For debugging, but not fast cases: $O_NONE $CLANG_DEBUG

# You can enable one of these:
# But they're very slow on OS X: 1000 tests per second to 5 per second
#export AFL_USE_ASAN=1
#export AFL_USE_MSAN=1
# As long as you also add:
# LDFLAGS="$CLANG_SAN_ADDRESS_LDFLAGS"
CC="$CLANG_AFL_FAST $CLANG_PROTECT $CLANG_SAN_TRAP"

# i386 doesn't work with afl
ARCH="x86_64"
echo "tor-afl-fast $ARCH"

# OPENSSL_LATEST uses the architecture in the linker paths
OPENSSL_LATEST="--with-openssl-dir=${OPENSSL_LATEST_DIR}-$ARCH"
CPPFLAGS_OPENSSL_LATEST="-I${OPENSSL_LATEST_DIR}-$ARCH/include -DOPENSSL_NO_DEPRECATED" # -DOPENSSL_USE_DEPRECATED
LDFLAGS_OPENSSL_LATEST="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"
LDFLAGS_OPENSSL_LATEST_STATIC="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"

OPENSSL="$OPENSSL_LATEST"
CPPFLAGS="$CPPFLAGS_OPENSSL_LATEST $CPPFLAGS_BASE"
LDFLAGS="$LDFLAGS_OPENSSL_LATEST_STATIC $LDFLAGS_BASE $DCE_LDFLAGS" #$CLANG_SAN_ADDRESS_LDFLAGS

LIBEVENT="--with-libevent-dir=$EXT_LIBDIR"

$MAKE clean \
&& echo ./configure --prefix=$PREFIX_BASE/tor-afl-fast-install-$ARCH \
  CC="$CC -arch $ARCH" \
  CPPFLAGS="$CPPFLAGS -include src/test/fuzz_prefix.h" \
  CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS $ASCIIDOC \
  --with-zlib-dir=$EXT_LIBDIR \
  --enable-static-libevent --enable-static-openssl --enable-static-zlib \
  --disable-transparent --disable-largefile --disable-libscrypt \
  --disable-gcc-hardening --enable-gcc-warnings-advisory \
  --enable-unittests \
&& ./configure --prefix=$PREFIX_BASE/tor-afl-fast-install-$ARCH \
  CC="$CC -arch $ARCH" \
  CPPFLAGS="$CPPFLAGS -include src/test/fuzz_prefix.h" \
  CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $OPENSSL $LIBEVENT $CONFIG_OPTS $ASCIIDOC \
  --with-zlib-dir=$EXT_LIBDIR \
  --enable-static-libevent --enable-static-openssl --enable-static-zlib \
  --disable-transparent --disable-largefile --disable-libscrypt \
  --disable-gcc-hardening --enable-gcc-warnings-advisory \
  --enable-unittests \
&& $MAKE \
&& date || exit 61

$MAKE install \
&& date || exit 64

make check-spaces || exit 65

unset CCACHE_DISABLE

fi # src/test/fuzz_prefix.h
fi # afl-fast

if [ "$1" = "harden" -o -z "$1" ]; then

# Disable extras, options, enable security, use (newer) libraries,
# avoid optimising too much
# we want --enable-static-tor but can't on OS X
# so we make almost everything else static
CC="$CLANG $O_MIN $CLANG_PROTECT $CLANG_SAN_TRAP $CLANG_SAN_ADDRESS"

for ARCH in $ARCHS; do
echo "tor-harden $ARCH"

# OPENSSL_LATEST uses the architecture in the linker paths
OPENSSL_LATEST="--with-openssl-dir=${OPENSSL_LATEST_DIR}-$ARCH"
CPPFLAGS_OPENSSL_LATEST="-I${OPENSSL_LATEST_DIR}-$ARCH/include -DOPENSSL_NO_DEPRECATED" # -DOPENSSL_USE_DEPRECATED
LDFLAGS_OPENSSL_LATEST="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"
LDFLAGS_OPENSSL_LATEST_STATIC="-L${OPENSSL_LATEST_DIR}-$ARCH/lib"

OPENSSL="$OPENSSL_LATEST"
CPPFLAGS="$CPPFLAGS_OPENSSL_LATEST $CPPFLAGS_BASE"
LDFLAGS="$CLANG_SAN_TRAP $LDFLAGS_OPENSSL_LATEST $LDFLAGS_BASE $FLTO_LDFLAGS $DCE_LDFLAGS"

LIBEVENT="--with-libevent-dir=$LIBEVENT_LATEST_DIR-$ARCH"
ZLIB="--with-zlib-dir=$ZLIB_LATEST_DIR-$ARCH"

$MAKE clean \
&& echo ./configure --prefix=$PREFIX_BASE/tor-harden-install-$ARCH \
  CC="$CC -arch $ARCH" CPPFLAGS="$CPPFLAGS" CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $CONFIG_OPTS $LIBEVENT $OPENSSL $ZLIB $ASCIIDOC \
  --enable-static-libevent --enable-static-zlib \
  --enable-static-openssl \
  --disable-transparent --disable-largefile \
  --disable-gcc-hardening \
  --enable-linker-hardening \
  --enable-expensive-hardening --enable-gcc-warnings \
&& ./configure --prefix=$PREFIX_BASE/tor-harden-install-$ARCH \
  CC="$CC -arch $ARCH" CPPFLAGS="$CPPFLAGS" CFLAGS="$FLTO_CFLAGS" \
  LDFLAGS="$LDFLAGS" \
  $CONFIG_OPTS $LIBEVENT $OPENSSL $ZLIB $ASCIIDOC \
  --enable-static-libevent --enable-static-zlib \
  --enable-static-openssl \
  --disable-transparent --disable-largefile \
  --disable-gcc-hardening \
  --enable-linker-hardening \
  --enable-expensive-hardening --enable-gcc-warnings \
&& $MAKE \
&& date || exit 71

# Allow address sanitizer to work with the tests
ASAN_OPTIONS=allow_user_segv_handler=1 $MAKE check \
&& src/test/bench \
&& date || exit 72
# src/test/bench only adds 9 functions

#/usr/libexec/ApplicationFirewall/socketfilterfw --add /test/tor-target/src/or/tor
$CHUTNEY_PATH/tools/kill-all-nodes.sh
# work around an issue where make test-network hangs on -j2
#make -j1 test-network \
src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR \
  || src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR --sleep 60 \
  || src/test/test-network.sh --flavour $CHUTNEY_FLAVOUR --sleep 300 \
&& date || exit 73
$CHUTNEY_PATH/tools/kill-current-nodes.sh

$MAKE install \
&& date || exit 74

done # for ARCH in $ARCHS;

make check-spaces || exit 76

#$MAKE clean
#date

fi # harden

exit 0
