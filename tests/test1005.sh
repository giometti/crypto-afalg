#!/bin/bash

echo -n "aes-128-cbc [bad-length-from-openssl]: "

. test-preset.inc

key=06a9214036b8a15b512e03d534120006
iv=3dafba429d9eb430b422da802c9fac41
pass='test-phrase'

# usage: check <ciphertext file> <y|n: accepted> <crypto-afalg key opts...>
check () {
	local enc=$1 ok=$2

	shift 2
	if crypto-afalg decrypt aes-128-cbc "$@" < $enc > $NAME.out 2> $NAME.err ; then
		[ $ok = y ] || fail=y
	else
		[ $ok = n ] || fail=y
	fi
	if [ $ok = y ] ; then
		diff -u $NAME.in $NAME.out || fail=y
	fi
}

fail=n
head -c 100 /dev/zero | tr '\0' 'a' > $NAME.in

openssl enc -aes-128-cbc -K $key -iv $iv < $NAME.in > $NAME.enc
head -c 50 $NAME.enc > $NAME.trunc
: > $NAME.empty
for f in $NAME.trunc $NAME.empty ; do
	if openssl enc -aes-128-cbc -d -K $key -iv $iv < $f > /dev/null 2>&1 ; then
		fail=y
	fi
done
check $NAME.enc y -K $key -V $iv
check $NAME.trunc n -K $key -V $iv
check $NAME.empty n -K $key -V $iv

# With a Salted__ header the length counts after its 16 bytes; no -S,
# since openssl writes no header for an explicit salt
if check-kalgo hash 'hmac(sha256)' ; then
	openssl enc -aes-128-cbc -pbkdf2 -k $pass < $NAME.in > $NAME.enc
	head -c $((16 + 50)) $NAME.enc > $NAME.trunc
	head -c 16 $NAME.enc > $NAME.empty
	for f in $NAME.trunc $NAME.empty ; do
		if openssl enc -aes-128-cbc -d -pbkdf2 -k $pass < $f > /dev/null 2>&1 ; then
			fail=y
		fi
	done
	check $NAME.enc y -P $pass
	check $NAME.trunc n -P $pass
	check $NAME.empty n -P $pass
fi

. test-end.inc
