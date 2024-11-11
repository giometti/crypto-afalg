#!/bin/bash

echo -n "hmac-sha256 [passstr-hmac-sha256]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
echo -n 'Single block msgSecond block msg' | \
	openssl dgst -sha256 -hmac 'my password' | cut -d ' ' -f2 > $NAME.in || fail=y
echo -n 'Single block msgSecond block msg' | \
	crypto-afalg hash hmac-sha-256 -P 'my password' > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
