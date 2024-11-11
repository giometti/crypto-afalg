#!/bin/bash

echo -n "aes-256-cbc [pbkdf2-salt-to-openssl]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
pass=$(openssl rand -base64 32)
salt=$(openssl rand -hex 8)
info_save pass salt
cat $NAME.in | \
	crypto-afalg encrypt aes-256-cbc -P $pass -T $salt | \
	openssl enc -aes-256-cbc -d \
			-pbkdf2 -k $pass -S $salt > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
