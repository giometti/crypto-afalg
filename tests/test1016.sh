#!/bin/bash

echo -n "aes-128-cbc [pbkdf2-passfile-newline-to-openssl]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
pass=$(openssl rand -base64 16)
info_save pass
echo "$pass" > $NAME.pass
cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc -p $NAME.pass | \
	openssl enc -aes-128-cbc -d -pbkdf2 -pass file:$NAME.pass > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
