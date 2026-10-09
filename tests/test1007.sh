#!/bin/bash

echo -n "aes-128-cbc [empty-openssl]: "

. test-preset.inc

key=06a9214036b8a15b512e03d534120006
iv=3dafba429d9eb430b422da802c9fac41
pass='test-phrase'

fail=n
: > $NAME.in

cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc -K $key -V $iv | \
	openssl enc -aes-128-cbc -d -K $key -iv $iv > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y
cat $NAME.in | \
	openssl enc -aes-128-cbc -K $key -iv $iv | \
	crypto-afalg decrypt aes-128-cbc -K $key -V $iv > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

if check-kalgo hash 'hmac(sha256)' ; then
	cat $NAME.in | \
		crypto-afalg encrypt aes-128-cbc -P $pass | \
		openssl enc -aes-128-cbc -d -pbkdf2 -k $pass > $NAME.out || fail=y
	diff -u $NAME.in $NAME.out || fail=y
	cat $NAME.in | \
		openssl enc -aes-128-cbc -pbkdf2 -k $pass | \
		crypto-afalg decrypt aes-128-cbc -P $pass > $NAME.out || fail=y
	diff -u $NAME.in $NAME.out || fail=y
fi

. test-end.inc
