#!/bin/bash

echo -n "aes-128-cbc [pbkdf2-passfile-truncation-to-openssl]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

# usage: check <pass file> <y|n: warning expected>
check () {
	cat $NAME.in | \
		crypto-afalg encrypt aes-128-cbc -p $1 2> $NAME.err | \
		openssl enc -aes-128-cbc -d -pbkdf2 -pass file:$1 > $NAME.out || fail=y
	diff -u $NAME.in $NAME.out || fail=y
	if [ $2 = y ] ; then
		grep -qF "$1" $NAME.err || fail=y
		grep -qF 'truncated to 1023' $NAME.err || fail=y
	elif [ -s $NAME.err ] ; then
		fail=y
	fi
}

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
openssl rand -base64 1500 | tr -d '\n' > $NAME.pass2000
head -c 1024 $NAME.pass2000 > $NAME.pass1024
head -c 1023 $NAME.pass2000 > $NAME.pass1023
head -c 1023 $NAME.pass2000 > $NAME.pass1023nl
echo >> $NAME.pass1023nl

check $NAME.pass2000 y
check $NAME.pass1024 y
check $NAME.pass1023 n
check $NAME.pass1023nl n

. test-end.inc
