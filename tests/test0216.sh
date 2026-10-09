#!/bin/bash

echo -n "hmac-sha256 [emptypass-hmac-sha256]: "

. test-preset.inc
if ! check-kalgo hash 'hmac(sha256)' ; then
	echo Skipped
	exit 0
fi

fail=n
# An empty passphrase is a valid HMAC key
echo -n 'Single block msgSecond block msg' | \
	openssl dgst -sha256 -hmac '' | cut -d ' ' -f2 > $NAME.in || fail=y
echo -n 'Single block msgSecond block msg' | \
	crypto-afalg hash hmac-sha-256 -P '' > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

# so a second key option after it is refused
key=5d0232491a6755490f230302484f37803a65b4c100c436b6f753e87702f5a34e
printf "$(echo $key | sed 's/../\\x&/g')" > $NAME.key
for opt in "-K $key" "-k $NAME.key" ; do
	if echo -n 'Single block msgSecond block msg' | \
		crypto-afalg hash hmac-sha-256 -P '' $opt \
			> /dev/null 2> $NAME.err ; then
		fail=y
	fi
	grep -q 'key already defined' $NAME.err || fail=y
done

. test-end.inc
