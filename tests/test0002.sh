#!/bin/bash

echo -n "aes-128-cbc [long-enc-dec]: "

. test-preset.inc

fail=n
dd if=/dev/zero bs=4K count=4 status=none > $NAME.in
cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc \
		-K 06a9214036b8a15b512e03d534120006 \
		-V 3dafba429d9eb430b422da802c9fac41 | \
	crypto-afalg decrypt aes-128-cbc \
		-K 06a9214036b8a15b512e03d534120006 \
		-V 3dafba429d9eb430b422da802c9fac41 > $NAME.out || fail=y
diff -b $NAME.in $NAME.out || fail=y

. test-end.inc
