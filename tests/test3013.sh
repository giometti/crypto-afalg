#!/bin/bash

echo -n "libkcrypto  [backend-select]: "

. test-preset.inc
. kc-test.inc

if ! test_cbc; then
	echo Skipped
	exit 0
fi
if ! command -v openssl > /dev/null 2>&1; then
	echo "Skipped (no openssl)"
	exit 0
fi
key_serial || {
	echo "Skipped (no keyring keys in libkcrypto)"
	exit 0
}
if ! keyctl new_session > /dev/null 2> $NAME.err; then
	echo "Skipped (keyctl new_session: $(cat $NAME.err))"
	exit 0
fi

fail=n
k=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
iv=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
u=$(printf "$(printf %s $k | sed 's/../\\x&/g')" | keyctl padd user $NAME @s)
user=spec:@s,user,$NAME
head -c 1000 /dev/urandom > $NAME.in

# The kernel's answer for a key that is no keycrypt key sends it to
# AF_ALG: openssl decrypts what comes out, the driver is the name given
for sel in auto afalg; do
	rm -f $NAME.meta
	kc-check cipher-backend $sel enc "$cbc" $user $iv 0 $NAME.meta \
		< $NAME.in > $NAME.enc || fail=y
	openssl enc -d -aes-256-cbc -K $k -iv $iv < $NAME.enc |
		cmp -s - $NAME.in || fail=y
	grep -qxF "driver: $cbc" $NAME.meta || fail=y
	grep -qxF "iv: $iv" $NAME.meta || fail=y
	grep -qxF "key_len: 0" $NAME.meta || fail=y
done

# No IV in encryption: the library draws one, a new one every time, and
# says which; a key in clear goes to AF_ALG too
for n in 1 2; do
	kc-check cipher-backend auto enc "$cbc" hex:$k - 0 $NAME.m$n \
		< $NAME.in > $NAME.e$n || fail=y
	ivn=$(sed -n 's/^iv: //p' $NAME.m$n)
	[ ${#ivn} -eq 32 ] || fail=y
	grep -qxF "key_len: 32" $NAME.m$n || fail=y
	openssl enc -d -aes-256-cbc -K $k -iv $ivn < $NAME.e$n |
		cmp -s - $NAME.in || fail=y
	kc-check cipher-backend auto dec "$cbc" $user $ivn 0 $NAME.dm \
		< $NAME.e$n | cmp -s - $NAME.in || fail=y
done
cmp -s $NAME.m1 $NAME.m2 && fail=y

# What only keycrypt takes, or only AF_ALG, and what neither takes
e='kc-check: status=2 errnum'
expect 2 "$e=89: a cipher through AF_ALG needs its name" \
	cipher-backend auto enc - $user $iv 0 $NAME.meta
expect 2 "$e=22: decryption needs the IV" \
	cipher-backend auto dec "$cbc" $user - 0 $NAME.meta
expect 2 "$e=95: the key $u is not a keycrypt key" \
	cipher-backend keycrypt enc - $user $iv 0 $NAME.meta
expect 2 "$e=22: a key in clear is not a keycrypt key" \
	cipher-backend keycrypt enc - hex:$k $iv 0 $NAME.meta
expect 2 "$e=22: a minimum tier is for keycrypt keys, and the key goes to AF_ALG" \
	cipher-backend auto enc "$cbc" $user $iv 20 $NAME.meta
expect 2 "$e=22: a minimum tier is for keycrypt keys, and the key goes to AF_ALG" \
	cipher-backend afalg enc "$cbc" $user $iv 20 $NAME.meta
expect 2 "$e=22: unknown backend 7" \
	cipher-backend 7 enc "$cbc" $user $iv 0 $NAME.meta

# A keyring key with a cipher whose IV no keycrypt key takes goes to
# AF_ALG without asking: 3DES, a block of 8, where the kernel has it
k24=${k:0:48}
u24=$(printf "$(printf %s $k24 | sed 's/../\\x&/g')" |
	keyctl padd user $NAME-24 @s)
iv8=a0a1a2a3a4a5a6a7
rc=0
kc-check cipher enc 'cbc(des3_ede)' spec:$u24 $iv8 < $NAME.in > $NAME.e3 \
	2> $NAME.err || rc=$?
if [ $rc -eq 0 ]; then
	openssl enc -d -des-ede3-cbc -K $k24 -iv $iv8 < $NAME.e3 2> /dev/null |
		cmp -s - $NAME.in || fail=y
elif [ $rc -ne 1 ]; then
	echo "cbc(des3_ede) with a keyring key: exit $rc, $(cat $NAME.err)"
	fail=y
fi
expect 2 "$e=95: the key $u24 is not a keycrypt key" \
	cipher-backend keycrypt enc 'cbc(des3_ede)' spec:$u24 $iv8 0 $NAME.meta

# AUTO asks keycrypt only about a key of its type, from the key's
# description: a revoked key fails as the kernel describes it, and one
# the caller may not view goes to AF_ALG
kr=$(printf "$(printf %s $k | sed 's/../\\x&/g')" | keyctl padd user $NAME-r @s)
keyctl revoke $kr
expect 3 "kc-check: status=3 errnum=128: key $kr: Key has been revoked" \
	cipher-backend auto enc "$cbc" spec:$kr $iv 0 $NAME.meta
kv=$(printf "$(printf %s $k | sed 's/../\\x&/g')" | keyctl padd user $NAME-v @s)
keyctl setperm $kv 0x08000000
if keyctl describe $kv > /dev/null 2>&1; then
	echo "keyctl setperm: the key $kv can still be viewed"
	fail=y
fi
rm -f $NAME.meta
kc-check cipher-backend auto enc "$cbc" spec:$kv $iv 0 $NAME.meta \
	< $NAME.in > $NAME.ev || fail=y
openssl enc -d -aes-256-cbc -K $k -iv $iv < $NAME.ev |
	cmp -s - $NAME.in || fail=y
grep -qxF "driver: $cbc" $NAME.meta || fail=y

# KEYCRYPT asks keycrypt for a key the caller may not view, and refuses
# one of another type without asking
expect 2 "$e=95: the key $kv is not a keycrypt key, or the kernel has no keycrypt" \
	cipher-backend keycrypt enc - spec:$kv $iv 0 $NAME.meta
expect 2 "$e=22: invalid IV length 8 for a keycrypt key" \
	cipher-backend keycrypt enc 'cbc(des3_ede)' spec:$kv $iv8 0 $NAME.meta

. test-end.inc
