#!/bin/bash

echo -n "aes-128-cbc [pbkdf2-no-header]: "

. test-preset.inc

if ! check-kalgo hash 'hmac(sha256)'; then
	echo Skipped
	exit 0
fi

# usage: refused <input file> <message>: decryption with a passphrase
# exits 1 with the message
refused () {
	local rc=0

	crypto-afalg decrypt aes-128-cbc -P secret < $1 > /dev/null \
		2> $NAME.err || rc=$?
	if [ $rc -ne 1 ] || ! grep -qxF "crypto-afalg: $2" $NAME.err; then
		echo "$1: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
}

fail=n

# A passphrase needs the salt of the "Salted__" header openssl writes
seq 1 100 | openssl enc -aes-128-cbc -pbkdf2 -pass pass:secret > $NAME.enc
crypto-afalg decrypt aes-128-cbc -P secret < $NAME.enc > $NAME.out || fail=y
seq 1 100 | cmp - $NAME.out || fail=y
seq 1 100 > $NAME.plain
refused $NAME.plain 'no salt in encrypted data'
printf 'Salted_' > $NAME.short
refused $NAME.short 'cannot read header'
head -c 15 $NAME.enc > $NAME.cut
refused $NAME.cut 'cannot read salt data'

. test-end.inc
