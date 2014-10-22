#!/bin/sh

MACPORTS_DIR=/opt/local

CONFIGURE=./configure
if [ ! -f $CONFIGURE ]; then
  cd ../..
fi

$CONFIGURE --with-libevent-dir=$MACPORTS_DIR --with-openssl-dir=$MACPORTS_DIR --disable-asciidoc
