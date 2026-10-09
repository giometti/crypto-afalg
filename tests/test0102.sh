#!/bin/bash

echo -n "input       [unreadable-stdin]: "

. test-preset.inc

key=06a9214036b8a15b512e03d534120006
iv=3dafba429d9eb430b422da802c9fac41

fail=n
mkdir -p $NAME.dir

# An unreadable stdin is an error, not an empty input
for cmd in "encrypt aes-128-cbc -K $key -V $iv" \
	   "decrypt aes-128-cbc -K $key -V $iv" \
	   "hash sha-256" ; do
	if crypto-afalg $cmd < $NAME.dir > /dev/null 2> $NAME.err ; then
		fail=y
	fi
	grep -q 'cannot read input' $NAME.err || fail=y
done

# A readable one still works
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc -K $key -V $iv | \
	crypto-afalg decrypt aes-128-cbc -K $key -V $iv > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y
sha256sum < $NAME.in | cut -d ' ' -f1 > $NAME.ref
crypto-afalg hash sha-256 < $NAME.in > $NAME.out || fail=y
diff -u $NAME.ref $NAME.out || fail=y

. test-end.inc
