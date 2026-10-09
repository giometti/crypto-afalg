#!/bin/bash

echo -n "aes-128-cbc [pbkdf2-iter-to-openssl]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
pass=$(openssl rand -base64 16)
iter=$((1 + $RANDOM % 5000))
info_save pass iter
cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc -P $pass --iterations $iter | \
	openssl enc -aes-128-cbc -d -pbkdf2 -iter $iter -k $pass > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
