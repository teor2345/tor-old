#!/bin/bash
MD5="md5"
INDIR="test-tmin"
OUTDIR="test-md5"
# Remove -v for silent operation, use mv to move
CP="cp -v"
for fname in "$INDIR"/*; do
  newname="$OUTDIR"/`cat "$fname" | "$MD5"`
  $CP "$fname" "$newname"
done
