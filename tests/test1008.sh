#!/bin/bash

echo -n "aes-128-cbc [hex-args-openssl]: "

. test-preset.inc

key=06a9214036b8a15b512e03d534120006
iv=3dafba429d9eb430b422da802c9fac41
salt=0123456789abcdef
pass='test-phrase'

# usage: refused <label> <crypto-afalg options...>
refused () {
	local label=$1

	shift
	if echo x | crypto-afalg encrypt aes-128-cbc "$@" \
			> /dev/null 2> $NAME.err ; then
		fail=y
	fi
	grep -q "cannot parse $label" $NAME.err || fail=y
}

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in

# Valid hex values stay compatible with openssl
cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc -K $key -V $iv | \
	openssl enc -aes-128-cbc -d -K $key -iv $iv > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

# A pair that is not two hex digits is refused
refused key -K 0g${key:2} -V $iv
refused key -K +f${key:2} -V $iv
refused iv -K $key -V ${iv:0:30}0g

if check-kalgo hash 'hmac(sha256)' ; then
	cat $NAME.in | \
		crypto-afalg encrypt aes-128-cbc -P $pass -T $salt | \
		openssl enc -aes-128-cbc -d -pbkdf2 -k $pass -S $salt \
			> $NAME.out || fail=y
	diff -u $NAME.in $NAME.out || fail=y
	refused salt -P $pass -T 0g${salt:2}
fi

. test-end.inc
