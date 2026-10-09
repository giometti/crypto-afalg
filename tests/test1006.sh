#!/bin/bash

echo -n "aes-128-cbc [bad-padding-from-openssl]: "

. test-preset.inc

key=06a9214036b8a15b512e03d534120006
iv=3dafba429d9eb430b422da802c9fac41

# usage: bad <last plaintext block, as printf format>
bad () {
	printf "aaaaaaaaaaaaaaaa$1" | \
		openssl enc -aes-128-cbc -nopad -K $key -iv $iv > $NAME.enc
	if openssl enc -aes-128-cbc -d -K $key -iv $iv \
			< $NAME.enc > /dev/null 2>&1 ; then
		fail=y
	fi
	if crypto-afalg decrypt aes-128-cbc -K $key -V $iv \
			< $NAME.enc > /dev/null 2>&1 ; then
		fail=y
	fi
}

# usage: good <plaintext length>
good () {
	head -c $1 /dev/zero | tr '\0' 'a' > $NAME.in
	cat $NAME.in | \
		crypto-afalg encrypt aes-128-cbc -K $key -V $iv | \
		openssl enc -aes-128-cbc -d -K $key -iv $iv > $NAME.out || fail=y
	diff -u $NAME.in $NAME.out || fail=y
	cat $NAME.in | \
		openssl enc -aes-128-cbc -K $key -iv $iv | \
		crypto-afalg decrypt aes-128-cbc -K $key -V $iv > $NAME.out || fail=y
	diff -u $NAME.in $NAME.out || fail=y
}

fail=n
bad 'aaaaaaaaaaaaaaa\x00'
bad 'aaaaaaaaaaaaaaa\x11'
bad 'aaaaaaaaaaaaaaa\x80'
bad 'aaaaaaaaaaa\x05\x99\x99\x99\x05'
good 31
good 32

. test-end.inc
