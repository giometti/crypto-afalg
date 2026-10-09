#!/bin/bash

echo -n "hmac-sha256 [passfile-hmac-sha256]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

# usage: check <key file> <file name to give crypto-afalg>
check () {
	echo -n 'Single block msgSecond block msg' | \
		openssl dgst -sha256 -mac HMAC \
			-macopt hexkey:$(od -An -tx1 -v $1 | tr -d ' \n') | \
		cut -d ' ' -f2 > $NAME.in || fail=y
	echo -n 'Single block msgSecond block msg' | \
		crypto-afalg hash hmac-sha-256 -p $2 > $NAME.out || fail=y
	diff -u $NAME.in $NAME.out || fail=y
}

fail=n
head -c 100 < /dev/urandom > $NAME.key100
head -c 2000 < /dev/urandom > $NAME.key2000
echo 'my password' > $NAME.keynl

check $NAME.key100 $NAME.key100
check $NAME.key2000 $NAME.key2000
check $NAME.key2000 <(cat $NAME.key2000)
check $NAME.keynl $NAME.keynl

. test-end.inc
