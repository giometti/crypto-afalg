#!/bin/bash

echo -n "sha-256     [simple-sha256]: "

. test-preset.inc

fail=n
echo -n 'Single block msgSecond block msg' | \
	sha256sum | cut -d ' ' -f1 > $NAME.in || fail=y
echo -n 'Single block msgSecond block msg' | \
	crypto-afalg hash sha-256 > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
