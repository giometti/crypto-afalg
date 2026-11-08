#!/bin/bash

echo -n "libkcrypto  [keycrypt]: "

. test-preset.inc
. kc-test.inc

# A keycrypt key made with the options of new in CRAF_TEST_KEYCRYPT (as
# backend=optee); with CRAF_TEST_KEYCRYPT_IMPORT=1 too, as root, one of a
# known value, which openssl checks
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

fail=n
iv=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
head -c 70000 /dev/urandom > $NAME.in

# With the variable set, a key that cannot be made is a failure; its
# serial into <var>
add () {	# <var> <name> <purpose>
	local id

	if ! id=$(keyctl add keycrypt $2 \
		"new aes256-cbc $3 $CRAF_TEST_KEYCRYPT" @s 2> $NAME.err); then
		echo "keyctl add keycrypt $2 ($3): $(cat $NAME.err)"
		echo KO!
		exit 1
	fi
	printf -v $1 %s "$id"
}

# Field <n> of the one line of /proc/keys of the key <name>, into <var>:
# "<name>: aes256-cbc <purpose> <tier> <backend> <origin>"
keyfield () {	# <var> <name> <n>
	local n v

	n=$(D=$2: awk '$9 == ENVIRON["D"]' /proc/keys | wc -l)
	v=$(D=$2: F=$3 awk '$9 == ENVIRON["D"] { print $ENVIRON["F"] }' \
		/proc/keys)
	if [ "$n" -ne 1 ] || [ -z "$v" ]; then
		echo "/proc/keys: $n lines for $2, field $3 \"$v\""
		echo KO!
		exit 1
	fi
	printf -v $1 %s "$v"
}
add kx $NAME-ed encrypt,decrypt
add ke $NAME-e encrypt
add kd $NAME-d decrypt
keyfield backend $NAME-ed 13

# The kernel draws the IV, says the backend; the same key decrypts
kc-check cipher-backend auto enc - spec:@s,keycrypt,$NAME-ed - 0 $NAME.meta \
	< $NAME.in > $NAME.enc || fail=y
grep -qxF "driver: keycrypt@$backend" $NAME.meta || fail=y
grep -qxF "key_len: 32" $NAME.meta || fail=y
kiv=$(sed -n 's/^iv: //p' $NAME.meta)
[ ${#kiv} -eq 32 ] || fail=y
kc-check cipher-backend keycrypt dec 'cbc(aes)' spec:$kx $kiv 0 $NAME.dm \
	< $NAME.enc | cmp -s - $NAME.in || fail=y
grep -qxF "iv: $kiv" $NAME.dm || fail=y

# The caller's IV, taken as it is
kc-check cipher-backend auto enc 'cbc(aes)' spec:$kx $iv 0 $NAME.meta \
	< $NAME.in > $NAME.enc2 || fail=y
grep -qxF "iv: $iv" $NAME.meta || fail=y
kc-check cipher-backend auto dec - spec:$kx $iv 0 $NAME.dm < $NAME.enc2 |
	cmp -s - $NAME.in || fail=y

# The kernel's IV is a new one every time, and never all zero
kc-check cipher-backend auto enc - spec:$kx - 0 $NAME.m2 < /dev/null \
	> /dev/null || fail=y
kiv2=$(sed -n 's/^iv: //p' $NAME.m2)
[ ${#kiv2} -eq 32 ] && [ "$kiv2" != "$kiv" ] || fail=y
[ "$kiv" != 00000000000000000000000000000000 ] || fail=y

# The key's algorithm and backend are its own; AF_ALG does not take it;
# its purpose is checked by the kernel
e='kc-check: status=2 errnum=22: the keycrypt key'
expect 2 "$e $kx is of cbc(aes), with its own backend: \"ecb(aes)\" is not for it" \
	cipher-backend auto enc 'ecb(aes)' spec:$kx $iv 0 $NAME.meta
expect 2 "$e $kx is of cbc(aes), with its own backend: \"cbc-aes-generic\" is not for it" \
	cipher-backend auto enc cbc-aes-generic spec:$kx $iv 0 $NAME.meta
rc=0
kc-check cipher-backend afalg enc 'cbc(aes)' spec:$kx $iv 0 $NAME.meta \
	< /dev/null > /dev/null 2> $NAME.err || rc=$?
if [ $rc -ne 3 ] || ! grep -q '^kc-check: status=3 errnum=92: ' $NAME.err; then
	echo "AF_ALG with a keycrypt key: exit $rc, $(cat $NAME.err)"
	fail=y
fi
e='kc-check: status=3 errnum=129: keycrypt, key'
expect 3 "$e $ke: the purpose of the key does not allow decryption" \
	cipher-backend auto dec - spec:$ke $iv 0 $NAME.meta
expect 3 "$e $kd: the purpose of the key does not allow encryption" \
	cipher-backend auto enc - spec:$kd - 0 $NAME.meta

# A tier above the key's is refused by the kernel
keyfield tier $NAME-ed 12
if [ "$tier" != hsm ]; then
	expect 3 "kc-check: status=3 errnum=1: keycrypt, key $kx: not permitted: the tier of the key is below the minimum asked or the system's (kernel.keys.keycrypt_system_tier), or a policy refuses it" \
		cipher-backend auto enc - spec:$kx - 30 $NAME.meta
fi

# At the key's own tier it opens: the kernel gives that minimum back
case $tier in
kernel) tn=10 ;;
engine) tn=15 ;;
tee) tn=20 ;;
hsm) tn=30 ;;
*) tn= ;;
esac
if [ -z "$tn" ]; then
	echo "/proc/keys: unknown tier \"$tier\""
	fail=y
else
	kc-check cipher-backend auto enc - spec:$kx - $tn $NAME.meta \
		< $NAME.in > /dev/null || fail=y
fi

# A keycrypt key the caller may not view goes to AF_ALG, which refuses
# it; the message says why it went there
add kn $NAME-n encrypt,decrypt
keyctl setperm $kn 0x08000000
rc=0
kc-check cipher-backend auto enc 'cbc(aes)' spec:$kn $iv 0 $NAME.meta \
	< $NAME.in > /dev/null 2> $NAME.err || rc=$?
if [ $rc -eq 0 ] ||
	! grep -qF '(the type of the key could not be read: Permission denied)' \
		$NAME.err; then
	echo "kc-check, a keycrypt key not viewable: exit $rc, $(cat $NAME.err)"
	fail=y
fi

# A key of a known value: openssl decrypts what keycrypt encrypts, and
# keycrypt what openssl encrypts
if [ "$CRAF_TEST_KEYCRYPT_IMPORT" = 1 ]; then
	k=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
	if ! command -v openssl > /dev/null 2>&1; then
		echo "CRAF_TEST_KEYCRYPT_IMPORT=1 needs openssl"
		fail=y
	elif ! ki=$(printf 'import aes256-cbc encrypt,decrypt %s %s' \
		"$CRAF_TEST_KEYCRYPT" $k |
		keyctl padd keycrypt $NAME-i @s 2> $NAME.err); then
		echo "keyctl padd keycrypt (import): $(cat $NAME.err)"
		fail=y
	else
		kc-check cipher-backend auto enc - spec:$ki $iv 0 $NAME.meta \
			< $NAME.in > $NAME.enc3 || fail=y
		openssl enc -d -aes-256-cbc -K $k -iv $iv < $NAME.enc3 |
			cmp -s - $NAME.in || fail=y
		openssl enc -e -aes-256-cbc -K $k -iv $iv < $NAME.in |
			kc-check cipher-backend auto dec - spec:$ki $iv 0 $NAME.dm |
			cmp -s - $NAME.in || fail=y
	fi
fi

. test-end.inc
