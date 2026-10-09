#!/bin/bash

echo -n "version     [format]: "

. test-preset.inc

fail=n
format='^v[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-g[0-9a-f]+(-dirty)?$'
crypto-afalg --version > $NAME.out || fail=y
read -r name version < $NAME.out
[ "$name" = crypto-afalg ] || fail=y
# In =~ a range class follows the locale
( LC_ALL=C; [[ $version =~ $format ]] ) || fail=y
# The version of the source tree the binary was built from
[ "$version" = "$($SRCDIR/tools/git-version.sh)" ] || fail=y

. test-end.inc
