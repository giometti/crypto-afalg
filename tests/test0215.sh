#!/bin/bash

echo -n "hmac-sha256 [4bytekey-hmac-sha256]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
pass=$(openssl rand -hex 2)
info_save pass
echo -n "$pass" > $NAME.pass
echo -n 'Single block msgSecond block msg' | \
	openssl dgst -sha256 -hmac $pass | cut -d ' ' -f2 > $NAME.in || fail=y
echo -n 'Single block msgSecond block msg' | \
	crypto-afalg hash hmac-sha-256 -P $pass > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y
echo -n 'Single block msgSecond block msg' | \
	crypto-afalg hash hmac-sha-256 -p $NAME.pass > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
