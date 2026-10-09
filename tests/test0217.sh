#!/bin/bash

echo -n "sha-256     [nokey-sha256]: "

. test-preset.inc

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
sha256sum < $NAME.in | cut -d ' ' -f1 > $NAME.ref
crypto-afalg hash sha-256 < $NAME.in > $NAME.out || fail=y
diff -u $NAME.ref $NAME.out || fail=y

# An algorithm without a key refuses every key option
head -c 200 < /dev/urandom > $NAME.key
key=5d0232491a6755490f230302484f37803a65b4c100c436b6f753e87702f5a34e
for opt in "-K $key" "-k $NAME.key" "-S 12345" "-P secret" "-p $NAME.key" ; do
	if crypto-afalg hash sha-256 $opt < $NAME.in > /dev/null 2> $NAME.err ; then
		fail=y
	fi
	grep -q 'sha-256 takes no key' $NAME.err || fail=y
done

. test-end.inc
