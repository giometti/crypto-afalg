#!/bin/bash

echo -n "craf        [backend-usage]: "

. test-preset.inc
. craf-test.inc

fail=n
craf_plain > $NAME.in
craf_fixed_archive $NAME.craf || fail=y
d=${#driver}

craf -help > $NAME.help || fail=y
grep -q -- '\[ -backend auto|afalg|keycrypt \] \[ -enc-min-tier <tier> \]' \
	$NAME.help || fail=y

# The values of the two options
craf_expect 2 '-backend: "openssl" is not auto, afalg or keycrypt' $NAME.in \
	seal -cipher-driver $driver -enc-key $good -backend openssl
craf_expect 2 '-enc-min-tier: "top" is not any, kernel, engine, tee or hsm' \
	$NAME.in seal -cipher-driver $driver -enc-key $good -enc-min-tier top
craf_expect 2 'info: takes -in only' $NAME.craf info -backend auto
craf_expect 2 'info: takes -in only' $NAME.craf info -enc-min-tier any

# A key that is no keycrypt key: keycrypt refuses it, and it takes no
# minimum tier; through AF_ALG, by choice too, it seals as before
craf_expect 2 "seal: the key $good is not a keycrypt key" \
	$NAME.in seal -backend keycrypt -enc-key $good
keycrypt_not_asked
craf_expect 2 'seal: a minimum tier is for keycrypt keys, and the key goes to AF_ALG' \
	$NAME.in seal -cipher-driver $driver -enc-key $good -enc-min-tier tee
craf_expect 2 'seal: -cipher-driver or -cipher-algo is required' $NAME.in \
	seal -backend afalg -enc-key $good
for b in afalg auto; do
	craf seal -backend $b -cipher-driver $driver -enc-key $good \
		< $NAME.in > $NAME.$b || fail=y
	craf unseal -backend $b -enc-key $good < $NAME.$b | cmp -s - $NAME.in ||
		fail=y
done

# An archive of AF_ALG: not for keycrypt, and no minimum tier
craf_expect 2 "unseal: -backend keycrypt, and the archive is of $driver" \
	$NAME.craf unseal -backend keycrypt -enc-key $good
craf_expect 2 'unseal: a minimum tier is for keycrypt keys, and the key goes to AF_ALG' \
	$NAME.craf unseal -enc-key $good -enc-min-tier tee
craf unseal -enc-key $good -enc-min-tier any < $NAME.craf |
	cmp -s - $NAME.in || fail=y

# The same archive under a header that names a keycrypt backend: a key
# that is none was the wrong key; through AF_ALG, with the driver given,
# the same bytes of key unseal it, since the data are the same AES
{
	craf_header $CRAF_IV keycrypt@optee
	tail -c +$((47 + d)) $NAME.craf
} > $NAME.kx
for b in auto keycrypt; do
	craf_expect 3 "unseal: keycrypt@optee needs a keycrypt key: the key $good is not a keycrypt key" \
		$NAME.kx unseal -enc-key $good -backend $b
	keycrypt_not_asked
done
craf_expect 2 'unseal: -any-driver chooses a driver of AF_ALG, and the archive is of keycrypt@optee' \
	$NAME.kx unseal -enc-key $good -any-driver
craf_expect 2 'unseal: -backend afalg, and the archive is of keycrypt@optee' \
	$NAME.kx unseal -enc-key $good -backend afalg
craf unseal -cipher-driver $driver -enc-key $good < $NAME.kx |
	cmp -s - $NAME.in || fail=y

# A -cipher-driver that names keycrypt is not looked for in /proc/crypto
craf_expect 3 "unseal: keycrypt@optee needs a keycrypt key: the key $good is not a keycrypt key" \
	$NAME.craf unseal -cipher-driver keycrypt@optee -enc-key $good
keycrypt_not_asked

. test-end.inc
