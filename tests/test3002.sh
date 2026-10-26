#!/bin/bash

echo -n "libkcrypto  [hash-keys]: "

. test-preset.inc
. kc-test.inc

if ! check-kalgo hash sha256 || ! check-kalgo hash 'hmac(sha256)'; then
	echo Skipped
	exit 0
fi

# usage: digest <reference file> <kc-check hash args...>: the digest of
# $NAME.in, through updates of every size, equals openssl's
digest () {
	local ref=$1

	shift
	kc-check hash "$@" < $NAME.in > $NAME.out || fail=y
	cmp $ref $NAME.out || fail=y
}

fail=n
key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
long=$(printf 'x%.0s' $(seq 64))

for size in 0 1 64 5000 50000; do
	head -c $size /dev/urandom > $NAME.in
	openssl dgst -sha256 < $NAME.in | sed 's/^.*= //' > $NAME.sha
	digest $NAME.sha sha256 -
	openssl dgst -sha256 -mac HMAC -macopt hexkey:$key < $NAME.in |
		sed 's/^.*= //' > $NAME.hmac
	digest $NAME.hmac 'hmac(sha256)' hex:$key
	# An empty HMAC key is a key too
	openssl dgst -sha256 -hmac '' < $NAME.in | sed 's/^.*= //' > $NAME.hmac
	digest $NAME.hmac 'hmac(sha256)' hex:
done

# What cannot be done, and the wrong arguments
expect 1 'kc-check: status=1 errnum=2: bind(): No such file or directory' \
	hash 'nosuch(sha256)' -
expect 2 'kc-check: status=2 errnum=36: bind(): File name too long' \
	hash "$long" -
expect 3 'kc-check: status=3 errnum=126: read(): Required key not available' \
	hash 'hmac(sha256)' -
expect 2 'kc-check: status=2 errnum=90: read(): Message too long' \
	hash sha256 - 31
expect 0 - hash sha256 - 32
# A final ends the hash, also when it had too little room
for room in 31 32; do
	for then in final update; do
		expect 2 'kc-check: status=2 errnum=22: the hash cannot be used any more' \
			hash-after sha256 $room $then
	done
done
expect 2 'kc-check: status=2 errnum=22: invalid key serial number "0"' \
	key-spec 0
expect 2 'kc-check: status=2 errnum=22: unknown keyring name "foo"' \
	key-spec foo,user,$NAME
expect 2 'kc-check: status=2 errnum=22: empty key type in "@s,,x"' \
	key-spec @s,,x
expect 2 'kc-check: status=2 errnum=22: empty key description in "@s,user,"' \
	key-spec @s,user,
expect 2 'kc-check: status=2 errnum=22: key type too long' \
	key-spec @s,$long,x

# Keyring keys, in a session keyring of the test's own
if key_serial && keyctl new_session > /dev/null 2>&1; then
	head -c 32 /dev/urandom > $NAME.key
	hex=$(od -An -tx1 -v $NAME.key | tr -d ' \n')
	id=$(keyctl padd user $NAME @s < $NAME.key)
	openssl dgst -sha256 -mac HMAC -macopt hexkey:$hex < $NAME.in |
		sed 's/^.*= //' > $NAME.hmac
	expect 0 - key-spec @s,user,$NAME
	[ "$(cat $NAME.got)" = "$id" ] || fail=y
	digest $NAME.hmac 'hmac(sha256)' spec:$id
	digest $NAME.hmac 'hmac(sha256)' spec:@s,user,$NAME

	expect 3 "kc-check: status=3 errnum=126: cannot get ID for user key $NAME-missing in keyring @s: Required key not available" \
		key-spec @s,user,$NAME-missing
	t32=$(printf 't%.0s' $(seq 32))
	expect 2 "kc-check: status=2 errnum=22: cannot get ID for $t32 key x in keyring @s: Invalid argument" \
		key-spec @s,$t32,x
	ring=$(keyctl newring $NAME-ring @s)
	keyctl padd user $NAME $ring < $NAME.key > /dev/null
	expect 2 "kc-check: status=2 errnum=76: more than one user key $NAME in keyring @s" \
		key-spec @s,user,$NAME
	keyctl revoke $id
	expect 3 'kc-check: status=3 errnum=128: setsockopt(ALG_SET_KEY_BY_KEY_SERIAL): Key has been revoked' \
		hash 'hmac(sha256)' spec:$id
else
	echo -n "(no keyring keys) "
fi

. test-end.inc
