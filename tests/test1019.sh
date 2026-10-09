#!/bin/bash

echo -n "aes-128-cbc [pbkdf2-longpassfile-openssl]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
openssl rand -base64 1500 | tr -d '\n' > $NAME.pass
cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc -p <(cat $NAME.pass) | \
	openssl enc -aes-128-cbc -d -pbkdf2 -pass file:$NAME.pass > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y
cat $NAME.in | \
	openssl enc -aes-128-cbc -pbkdf2 -pass file:$NAME.pass | \
	crypto-afalg decrypt aes-128-cbc -p $NAME.pass > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
