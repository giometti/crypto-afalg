#!/bin/bash

echo -n "hmac-sha256 [simple-hmac-sha256]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
echo -n 'Single block msgSecond block msg' | \
	openssl dgst -sha256 -mac HMAC -macopt hexkey:5d0232491a6755490f230302484f37803a65b4c100c436b6f753e87702f5a34e | cut -d ' ' -f2 > $NAME.in || fail=y
echo -n 'Single block msgSecond block msg' | \
	crypto-afalg hash hmac-sha-256 -K 5d0232491a6755490f230302484f37803a65b4c100c436b6f753e87702f5a34e > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
