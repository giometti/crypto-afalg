#!/bin/bash

echo -n "keyserial   [keycrypt]: "

. test-preset.inc

# A keycrypt key made with the options of new in CRAF_TEST_KEYCRYPT (as
# backend=optee), as libkcrypto's [keycrypt] makes it
if [ -z "$CRAF_TEST_KEYCRYPT" ]; then
	echo "Skipped (CRAF_TEST_KEYCRYPT not set)"
	exit 0
fi
# With the variable set, what the test needs and lacks is a failure
if ! keyctl new_session > /dev/null 2> $NAME.err; then
	echo "keyctl new_session: $(cat $NAME.err)"
	echo KO!
	exit 1
fi
if ! kx=$(keyctl add keycrypt $NAME \
	"new aes256-cbc encrypt,decrypt $CRAF_TEST_KEYCRYPT" @s 2> $NAME.err); then
	echo "keyctl add keycrypt $NAME: $(cat $NAME.err)"
	echo KO!
	exit 1
fi

fail=n
iv=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
head -c 1000 /dev/urandom > $NAME.in

# -S takes it as any keyring key, through keycrypt
crypto-afalg encrypt aes-256-cbc -S $kx -V $iv < $NAME.in > $NAME.enc ||
	fail=y
crypto-afalg decrypt aes-256-cbc -S $kx -V $iv < $NAME.enc |
	cmp -s - $NAME.in || fail=y

# Its length is its own: a cipher of another one is refused
rc=0
crypto-afalg encrypt aes-128-cbc -S $kx -V $iv < $NAME.in > /dev/null \
	2> $NAME.err || rc=$?
if [ $rc -ne 1 ] || ! grep -qxF \
	'crypto-afalg: -S: the key is of 32 bytes, aes-128-cbc takes 16' \
	$NAME.err; then
	echo "aes-128-cbc with a keycrypt key: exit $rc, $(cat $NAME.err)"
	fail=y
fi

. test-end.inc
