#!/bin/bash

echo -n "aes-256-cbc [pbkdf2-from-openssl]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
pass=$(openssl rand -base64 32)
info_save pass
cat $NAME.in | \
	openssl enc -aes-256-cbc -pbkdf2 -k $pass |
	crypto-afalg decrypt aes-256-cbc -P $pass > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
