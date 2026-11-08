#!/bin/bash

echo -n "craf        [keycrypt]: "

. test-preset.inc

# Keycrypt keys made with the options of new in CRAF_TEST_KEYCRYPT (as
# backend=optee); with CRAF_TEST_KEYCRYPT_IMPORT=1 too, as root, one of a
# known value, which openssl and AF_ALG check
if [ -z "$CRAF_TEST_KEYCRYPT" ]; then
	echo "Skipped (CRAF_TEST_KEYCRYPT not set)"
	exit 0
fi
# With the variable set, what the test needs and lacks is a failure; the
# cases of AF_ALG run where it is usable, and where it is not the others
# run all the same and the test fails at the end, with the reason
if ! keyctl new_session > /dev/null 2> $NAME.err; then
	echo "keyctl new_session: $(cat $NAME.err)"
	echo KO!
	exit 1
fi
CRAF_AFALG_OPTIONAL=y
. craf-test.inc

fail=n
craf_plain > $NAME.in
head -c 70000 /dev/urandom >> $NAME.in

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
keyfield tier $NAME-ed 12

# Sealed with no driver: the header names the key's backend, as info
# shows; the same key unseals it, given by serial or by spec
craf seal -enc-key $kx < $NAME.in > $NAME.craf || fail=y
craf info < $NAME.craf > $NAME.info || fail=y
grep -qxF "cipher_driver: keycrypt@$backend" $NAME.info || fail=y
grep -qxF 'key_source: serial' $NAME.info || fail=y
craf unseal -enc-key $kx < $NAME.craf | cmp -s - $NAME.in || fail=y
craf unseal -enc-key @s,keycrypt,$NAME-ed -backend keycrypt < $NAME.craf |
	cmp -s - $NAME.in || fail=y
craf unseal -cipher-driver keycrypt@$backend -enc-key $kx < $NAME.craf |
	cmp -s - $NAME.in || fail=y
craf seal -backend keycrypt -enc-key $kx -enc-min-tier any < $NAME.in |
	craf unseal -enc-key $kx | cmp -s - $NAME.in || fail=y

# The algorithm and the backend are the key's: no driver for seal, and
# AF_ALG does not take the key
if [ -n "$driver" ]; then
	craf_expect 2 "seal: the keycrypt key $kx is of cbc(aes), with its own backend: \"$driver\" is not for it" \
		$NAME.in seal -cipher-driver $driver -enc-key $kx
	craf_expect 2 'is of cbc(aes), with its own backend:' \
		$NAME.in seal -cipher-algo 'cbc(aes)' -enc-key $kx
	craf_expect 3 "cannot open \"$driver\":" \
		$NAME.in seal -backend afalg -cipher-driver $driver -enc-key $kx
fi
craf_expect 2 "unseal: -backend afalg, and the archive is of keycrypt@$backend" \
	$NAME.craf unseal -backend afalg -enc-key $kx

# Another backend in the header, or given: refused, unless given
craf_expect 3 "unseal: the archive is of keycrypt@other, the key is run by keycrypt@$backend: -cipher-driver keycrypt@$backend to unseal it with this key" \
	$NAME.craf unseal -cipher-driver keycrypt@other -enc-key $kx

# The purpose and the tier, as the kernel checks them
craf_expect 3 "keycrypt, key $kd: the purpose of the key does not allow encryption" \
	$NAME.in seal -enc-key $kd
craf seal -enc-key $ke < $NAME.in > $NAME.e || fail=y
craf_expect 3 "keycrypt, key $ke: the purpose of the key does not allow decryption" \
	$NAME.e unseal -enc-key $ke
if [ "$tier" != hsm ]; then
	craf_expect 3 "keycrypt, key $kx: not permitted: the tier of the key is below the minimum asked" \
		$NAME.in seal -enc-key $kx -enc-min-tier hsm
	craf_expect 3 "keycrypt, key $kx: not permitted: the tier of the key is below the minimum asked" \
		$NAME.craf unseal -enc-key $kx -enc-min-tier hsm
fi

# A key of a known value: the data are AES-256-CBC that openssl and
# AF_ALG read with the same bytes of key, in both directions
if [ "$CRAF_TEST_KEYCRYPT_IMPORT" = 1 ] && [ -n "$driver" ]; then
	if ! ki=$(printf 'import aes256-cbc encrypt,decrypt %s %s' \
		"$CRAF_TEST_KEYCRYPT" $CRAF_KEY_GOOD |
		keyctl padd keycrypt $NAME-i @s 2> $NAME.err); then
		echo "keyctl padd keycrypt (import): $(cat $NAME.err)"
		fail=y
	else
		craf seal -enc-key $ki < $NAME.in > $NAME.ki || fail=y
		iv=$(craf info < $NAME.ki | sed -n 's/^iv: //p')
		hl=$(craf info < $NAME.ki | sed -n 's/^hdr_len: //p')
		tail -c +$((hl + 1)) $NAME.ki |
			openssl enc -d -aes-256-cbc -K $CRAF_KEY_GOOD -iv $iv |
			cmp -s - $NAME.in || fail=y
		craf unseal -cipher-driver $driver -enc-key $good < $NAME.ki |
			cmp -s - $NAME.in || fail=y
		craf unseal -cipher-driver keycrypt@$backend -enc-key $ki \
			< $NAME.craf > /dev/null 2>&1 && fail=y
		craf_fixed_archive $NAME.af
		craf unseal -cipher-driver keycrypt@$backend -enc-key $ki \
			< $NAME.af | cmp -s - <(craf_plain) || fail=y
	fi
fi

# What AF_ALG lacks left its cases out: a failure
if [ -n "$craf_no_afalg" ]; then
	echo "the cases of AF_ALG did not run: $craf_no_afalg"
	fail=y
fi

. test-end.inc
