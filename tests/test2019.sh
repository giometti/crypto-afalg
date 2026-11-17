#!/bin/bash

echo -n "craf        [enc-key]: "

. test-preset.inc
. craf-test.inc
. enc-test.inc

fail=n
k16=000102030405060708090a0b0c0d0e0f
u16=$(craf_add_key $NAME-16 $k16)

craf -help > $NAME.help || fail=y
grep -q -- '-enc-key <key> -iv <hex> \[ -cipher-driver <driver> \]' \
	$NAME.help || fail=y
grep -qF -- '[ -<openssl cipher> | -cipher-algo <cipher> [ -cipher-key-len <n> ] ]' \
	$NAME.help || fail=y

# What openssl enc -K -iv writes and reads, every length around the block
# and the 8192 bytes read at once; -e is the default, as for openssl
for size in 0 1 15 16 17 8191 8192 8193 70000; do
	head -c $size /dev/urandom > $NAME.in
	craf enc -e -aes-256-cbc -enc-key $good -iv $CRAF_IV < $NAME.in \
		> $NAME.enc 2> /dev/null || fail=y
	openssl enc -d -aes-256-cbc -K $CRAF_KEY_GOOD -iv $CRAF_IV \
		< $NAME.enc | cmp -s - $NAME.in || fail=y
	openssl enc -e -aes-256-cbc -K $CRAF_KEY_GOOD -iv $CRAF_IV \
		< $NAME.in > $NAME.ref
	cmp -s $NAME.enc $NAME.ref || fail=y
	craf enc -d -aes-256-cbc -enc-key @s,user,$NAME-good -iv $CRAF_IV \
		< $NAME.ref 2> /dev/null | cmp -s - $NAME.in || fail=y
done
craf enc -aes-256-cbc -enc-key $good -iv $CRAF_IV < $NAME.in 2> /dev/null |
	cmp -s - $NAME.ref || fail=y

# The cipher by the kernel's name, a driver, AES-128 with a key of 16
craf enc -cipher-algo 'cbc(aes)' -cipher-key-len 32 -enc-key $good \
	-iv $CRAF_IV < $NAME.in | cmp -s - $NAME.ref || fail=y
craf enc -aes-256-cbc -cipher-driver $driver -enc-key $good -iv $CRAF_IV \
	< $NAME.in 2> /dev/null | cmp -s - $NAME.ref || fail=y
openssl enc -e -aes-128-cbc -K $k16 -iv $CRAF_IV < $NAME.in > $NAME.r16
craf enc -aes-128-cbc -enc-key $u16 -iv $CRAF_IV < $NAME.in 2> /dev/null |
	cmp -s - $NAME.r16 || fail=y

# A cipher whose IV no keycrypt key takes goes to AF_ALG all the same:
# 3DES, a block of 8, where the kernel has it
k24=${CRAF_KEY_GOOD:0:48}
u24=$(craf_add_key $NAME-24 $k24)
iv8=a0a1a2a3a4a5a6a7
rc=0
craf enc -des-ede3-cbc -enc-key $u24 -iv $iv8 < $NAME.in > $NAME.e3 \
	2> $NAME.err || rc=$?
if [ $rc -eq 0 ]; then
	openssl enc -d -des-ede3-cbc -K $k24 -iv $iv8 < $NAME.e3 \
		2> /dev/null | cmp -s - $NAME.in || fail=y
elif [ $rc -ne 3 ] || ! grep -q 'not available' $NAME.err; then
	echo "craf enc -des-ede3-cbc: exit $rc, $(cat $NAME.err)"
	fail=y
fi

# A key whose length cannot be read back: the kernel takes it as it is,
# and a warning says so
lg=$(craf_bytes $CRAF_KEY_GOOD | keyctl padd logon craf:$NAME @s)
craf enc -aes-256-cbc -enc-key $lg -iv $CRAF_IV < $NAME.in 2> $NAME.err |
	cmp -s - $NAME.ref || fail=y
grep -qxF 'craf: warning: -enc-key: the length of the key cannot be read: 32 bytes are needed, and the kernel takes another length as it is' \
	$NAME.err || fail=y

# What openssl refuses after decrypting, craf too: the blocks before go
# out, the exit status is 1
head -c 100 $NAME.ref > $NAME.cut
enc_expect 1 'bad decrypt (wrong final block length)' $NAME.cut -d \
	-aes-256-cbc -enc-key $good -iv $CRAF_IV
enc_expect 1 'bad decrypt (wrong padding)' $NAME.ref -d -aes-256-cbc \
	-enc-key $bad -iv a0a1a2a3a4a5a6a7a8a9aaabacadaeae

# The key is the key: no passphrase, no derivation; the IV the cipher's
ek=(-aes-256-cbc -enc-key $good -iv $CRAF_IV)
for opt in -pbkdf2 '-iter 10' '-md sha256' '-k x' "-kfile $NAME.in" \
	'-pass pass:x'; do
	enc_expect 2 'enc: -enc-key is the key: -pbkdf2, -iter, -md, -k, -kfile and -pass are not for it' \
		$NAME.in "${ek[@]}" $opt
done
enc_expect 2 'enc: -enc-key needs -iv' $NAME.in -aes-256-cbc -enc-key $good
enc_expect 2 '-iv: "a0a1" is not 32 hex digits' $NAME.in -aes-256-cbc \
	-enc-key $good -iv a0a1
enc_expect 2 '-iv: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0" is not 32 hex digits' \
	$NAME.in -aes-256-cbc -enc-key $good -iv a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0
enc_expect 2 '-iv: "a0a1a2a3a4a5a6a7a8a9aaabacadaeag" is not 32 hex digits' \
	$NAME.in -aes-256-cbc -enc-key $good -iv a0a1a2a3a4a5a6a7a8a9aaabacadaeag
if [ "$(grep -c -e '-iv: ' $NAME.err)" -ne 1 ]; then
	echo "craf enc, an -iv of 32 characters not hex: $(cat $NAME.err)"
	fail=y
fi
enc_expect 2 "-enc-key: user key $good is 32 bytes, not 16" $NAME.in \
	-aes-128-cbc -enc-key $good -iv $CRAF_IV
enc_expect 2 'names an algorithm, not a driver' $NAME.in "${ek[@]}" \
	-cipher-driver 'cbc(aes)'
enc_expect 3 '-enc-key: ' $NAME.in -aes-256-cbc -enc-key @s,user,$NAME-none \
	-iv $CRAF_IV
craf enc "${ek[@]}" -salt < $NAME.in > /dev/null 2> $NAME.err || fail=y
grep -qxF 'craf: warning: -salt has no effect with -enc-key' $NAME.err ||
	fail=y

# A key whose type cannot be read goes to AF_ALG, where craf cannot
# describe it either: a revoked key fails as the kernel describes it
kr=$(craf_add_key $NAME-r $CRAF_KEY_GOOD)
keyctl revoke $kr
enc_expect 3 "-enc-key: cannot describe key $kr: Key has been revoked" $NAME.in \
	-aes-256-cbc -enc-key $kr -iv $CRAF_IV

# No cipher: only a key keycrypt runs brings its own; a key of another
# type, -backend afalg and a key without View, the only one -backend
# keycrypt may still run, are a wrong usage, any other key craf cannot
# describe (revoked, gone) a failure
nc='enc: a cipher is required, as -aes-256-cbc or -cipher-algo, for a key keycrypt does not run'
for d in -e -d; do
	enc_expect 2 "$nc: the key $good is not a keycrypt key" $NAME.ref $d \
		-enc-key $good -iv $CRAF_IV
	keycrypt_not_asked
done
enc_expect 2 "$nc, and with -backend afalg keycrypt runs none" $NAME.in \
	-backend afalg -enc-key $good -iv $CRAF_IV
enc_expect 2 "enc: the key $good is not a keycrypt key" $NAME.in \
	-backend keycrypt -enc-key $good -iv $CRAF_IV
keycrypt_not_asked
enc_expect 3 "-enc-key: cannot describe key $kr: Key has been revoked" $NAME.in \
	-enc-key $kr -iv $CRAF_IV
enc_expect 3 "enc: cannot open the key's cipher: key $kr: Key has been revoked" \
	$NAME.in -backend keycrypt -enc-key $kr -iv $CRAF_IV
kg=$(craf_add_key $NAME-g $CRAF_KEY_GOOD)
keyctl invalidate $kg
enc_expect 3 "-enc-key: cannot describe key $kg: Required key not available" \
	$NAME.in -enc-key $kg -iv $CRAF_IV
kv=$(craf_add_key $NAME-v $CRAF_KEY_GOOD)
keyctl setperm $kv 0x08000000
if keyctl describe $kv > /dev/null 2>&1; then
	echo "keyctl setperm: the key $kv can still be viewed"
	fail=y
fi
enc_expect 2 "$nc: the type of the key $kv cannot be read (Permission denied), -backend keycrypt lets the key decide" \
	$NAME.in -enc-key $kv -iv $CRAF_IV
enc_expect 2 'enc: -cipher-key-len is for -cipher-algo' $NAME.in \
	-cipher-key-len 32 -enc-key $good -iv $CRAF_IV

# -backend and -enc-min-tier, as for seal: auto and afalg take a key of
# another type to AF_ALG, keycrypt refuses it, and a minimum tier is for
# a keycrypt key only
for b in auto afalg; do
	craf enc "${ek[@]}" -backend $b < $NAME.in 2> /dev/null |
		cmp -s - $NAME.ref || fail=y
done
craf enc "${ek[@]}" -enc-min-tier any < $NAME.in 2> /dev/null |
	cmp -s - $NAME.ref || fail=y
enc_expect 2 "enc: the key $good is not a keycrypt key" \
	$NAME.in "${ek[@]}" -backend keycrypt
keycrypt_not_asked
enc_expect 2 '-iv: "a0a1a2a3a4a5a6a7" is not 32 hex digits' $NAME.in \
	-aes-256-cbc -enc-key $good -iv a0a1a2a3a4a5a6a7 -backend keycrypt
enc_expect 2 'enc: a minimum tier is for keycrypt keys, and the key goes to AF_ALG' \
	$NAME.in "${ek[@]}" -enc-min-tier tee
for opt in '-backend auto' '-enc-min-tier any'; do
	enc_expect 2 'enc: -backend and -enc-min-tier are for -enc-key' \
		$NAME.in -d -aes-256-cbc -pbkdf2 -k x $opt
done
enc_expect 2 '-backend: "openssl" is not auto, afalg or keycrypt' $NAME.in \
	"${ek[@]}" -backend openssl
enc_expect 2 '-enc-min-tier: "top" is not any, kernel, engine, tee or hsm' \
	$NAME.in "${ek[@]}" -enc-min-tier top

. test-end.inc
