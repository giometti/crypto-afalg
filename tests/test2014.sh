#!/bin/bash

echo -n "craf        [dgst-verify-key]: "

. test-preset.inc
. kc-test.inc
. dgst-test.inc

keyctl new_session > /dev/null 2> $NAME.err ||
	dgst_skip "keyctl new_session: $(cat $NAME.err)"

fail=n

# The material, made by openssl, the oracle: an RSA key, two certificates
# of it, data and their signature
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
	-out $NAME.pem 2> /dev/null
for cn in one two; do
	openssl req -x509 -new -key $NAME.pem -subj /CN=$cn -days 1 \
		-addext subjectKeyIdentifier=hash -outform DER \
		-out $NAME.$cn 2> /dev/null
done
head -c 100000 /dev/urandom > $NAME.in
openssl dgst -sha256 -sign $NAME.pem -out $NAME.sig $NAME.in

# A kernel without asymmetric keys or X.509 certificates skips the test,
# with its reason
if ! a=$(keyctl padd asymmetric "" @s < $NAME.one 2> $NAME.err); then
	dgst_skip "$(cat $NAME.err)"
fi
desc=$(keyctl rdescribe $a | cut -d';' -f5-)
skid=${desc##*: }

# The key by its serial, by the kernel's search and by its description
for key in $a "@s,asymmetric,id:$skid" "@s,asymmetric,$desc"; do
	dgst_expect 0 '' -verify-key "$key" -signature $NAME.sig $NAME.in
	if [ "$(cat $NAME.out)" != "Verified OK" ]; then
		echo "craf dgst -verify-key $key: $(cat $NAME.err $NAME.out)"
		fail=y
	fi
done

# -keyform, for a key that is no file, has no effect
dgst_expect 0 'craf: warning: -keyform has no effect without -verify' \
	-keyform PEM -verify-key $a -signature $NAME.sig $NAME.in

# What does not hold: refused
cp $NAME.in $NAME.bad
flip $NAME.bad 5000
dgst_expect 1 'dgst: verification failure: ' \
	-verify-key $a -signature $NAME.sig $NAME.bad
if [ "$(cat $NAME.out)" != "Verification failure" ]; then
	echo "craf dgst -verify-key, altered data: $(cat $NAME.out)"
	fail=y
fi

# A key that is not asymmetric: seen on the command line, a wrong usage;
# by its serial, the kernel says, and craf could not
u=$(keyctl add user $NAME-user 0123456789 @s)
dgst_expect 2 '-verify-key: a key of type "user", only asymmetric verifies' \
	-verify-key "@s,user,$NAME-user" -signature $NAME.sig $NAME.in
dgst_expect 2 '-verify-key: a key of type "user", only asymmetric verifies' \
	-verify-key "user,$NAME-user" -signature $NAME.sig $NAME.in
dgst_expect 3 "dgst: the key cannot be used with \"enc=pkcs1 hash=sha256\"" \
	-verify-key $u -signature $NAME.sig $NAME.in

# A key that is not there, a spec that names two: as for -enc-key
dgst_expect 3 '-verify-key: cannot get ID for asymmetric key id:00 in keyring @s' \
	-verify-key "@s,asymmetric,id:00" -signature $NAME.sig $NAME.in
keyctl padd asymmetric "" @s < $NAME.two > /dev/null
dgst_expect 2 "-verify-key: more than one asymmetric key id:$skid in keyring @s" \
	-verify-key "@s,asymmetric,id:$skid" -signature $NAME.sig $NAME.in
dgst_expect 2 '-verify-key: unknown keyring name "@x"' \
	-verify-key "@x,asymmetric,id:$skid" -signature $NAME.sig $NAME.in

# Wrong usage, exit status 2
dgst_expect 2 'dgst: give -verify or -verify-key, not both' \
	-verify $NAME.pem -verify-key $a -signature $NAME.sig $NAME.in
dgst_expect 2 'dgst: -verify-key needs -signature' -verify-key $a $NAME.in

. test-end.inc
