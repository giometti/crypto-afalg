#!/bin/bash

echo -n "libkcrypto  [spec-search]: "

. test-preset.inc
. kc-test.inc

if ! command -v openssl > /dev/null 2>&1; then
	echo "Skipped (no openssl)"
	exit 0
fi
if ! keyctl new_session > /dev/null 2> $NAME.err; then
	echo "Skipped (keyctl new_session: $(cat $NAME.err))"
	exit 0
fi

# Three certificates of one key, with the same subject key identifier,
# the end of the description the kernel gives them
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
	-out $NAME.pem 2> /dev/null
for cn in one two three; do
	openssl req -x509 -new -key $NAME.pem -subj /CN=$cn -days 1 \
		-addext subjectKeyIdentifier=hash -outform DER \
		-out $NAME.$cn 2> /dev/null
done

# A kernel without asymmetric keys or X.509 certificates skips the test,
# with its reason
if ! a=$(keyctl padd asymmetric "" @s < $NAME.one 2> $NAME.err); then
	echo "Skipped ($(cat $NAME.err))"
	exit 0
fi

fail=n
skid=$(keyctl rdescribe $a | sed 's/.*: //')
tail=${skid: -8}

# The kernel finds an asymmetric key by "id:" and the end of its
# identifier, not by its description only
for spec in "@s,asymmetric,id:$skid" "@s,asymmetric,id:$tail" \
	"@s,asymmetric,one: $skid"; do
	expect 0 - key-spec "$spec"
	if [ "$(cat $NAME.got)" != "$a" ]; then
		echo "key-spec $spec: $(cat $NAME.got), not $a"
		fail=y
	fi
done

# The same search finds the second certificate too: refused, while its
# description is held once
b=$(keyctl padd asymmetric "" @s < $NAME.two)
for id in $skid $tail; do
	expect 2 "kc-check: status=2 errnum=76: more than one asymmetric key id:$id in keyring @s" \
		key-spec "@s,asymmetric,id:$id"
done
expect 0 - key-spec "@s,asymmetric,one: $skid"

# A key of the type that the library cannot ask the kernel about, here
# one it cannot link, leaves the answer unknown: a failure, not a pass;
# a description the kernel compares as a string needs no asking
keyctl setperm $b 0x2b010000
expect 3 "kc-check: status=3 errnum=13: cannot tell whether the key $b is also asymmetric key id:$skid: Permission denied" \
	key-spec "@s,asymmetric,id:$skid"
expect 0 - key-spec "@s,asymmetric,one: $skid"

# A key found twice is refused, a key that cannot be asked about
# notwithstanding
keyctl padd asymmetric "" @s < $NAME.three > /dev/null
expect 2 "kc-check: status=2 errnum=76: more than one asymmetric key id:$skid in keyring @s" \
	key-spec "@s,asymmetric,id:$skid"

# A user key is compared by its description: one the library cannot link
# beside it changes nothing
ua=$(keyctl add user $NAME-a aaaa @s)
ub=$(keyctl add user $NAME-b bbbb @s)
keyctl setperm $ub 0x2f010000
expect 0 - key-spec "@s,user,$NAME-a"
if [ "$(cat $NAME.got)" != "$ua" ]; then
	echo "key-spec @s,user,$NAME-a: $(cat $NAME.got), not $ua"
	fail=y
fi

# A key that cannot even be described, here one with the description
# in a keyring linked to @s, leaves the answer unknown
kr=$(keyctl newring $NAME-ring @s)
uc=$(keyctl add user $NAME-a cccc $kr)
keyctl setperm $uc 0x0c000000
expect 3 "kc-check: status=3 errnum=13: cannot tell whether the key $uc is also user key $NAME-a: Permission denied" \
	key-spec "@s,user,$NAME-a"

. test-end.inc
