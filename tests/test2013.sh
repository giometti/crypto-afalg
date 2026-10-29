#!/bin/bash

echo -n "craf        [dgst-verify]: "

. test-preset.inc
. kc-test.inc
. dgst-test.inc

fail=n

# The material, made by openssl, the oracle: an RSA key in the forms
# openssl dgst -verify takes, a certificate, data and their signatures
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
	-out $NAME.pem 2> /dev/null
openssl pkey -in $NAME.pem -pubout -out $NAME.pub.pem
openssl pkey -in $NAME.pem -pubout -outform DER -out $NAME.pub.der
openssl rsa -in $NAME.pem -RSAPublicKey_out -out $NAME.rsa.pem 2> /dev/null
openssl req -x509 -new -key $NAME.pem -subj /CN=$NAME -days 1 \
	-out $NAME.crt 2> /dev/null
head -c 100000 /dev/urandom > $NAME.in
openssl dgst -sha256 -sign $NAME.pem -out $NAME.sig $NAME.in
openssl dgst -sha384 -sign $NAME.pem -out $NAME.sig384 $NAME.in

# A kernel without asymmetric keys or X.509 certificates skips the test,
# with its reason: the kernel says, in a session keyring of the test, not
# craf, whose failure to load a key is a failure
keyctl new_session > /dev/null 2> $NAME.err ||
	dgst_skip "keyctl new_session: $(cat $NAME.err)"
openssl x509 -in $NAME.crt -outform DER -out $NAME.crt.der
if ! keyctl padd asymmetric "" @s < $NAME.crt.der > /dev/null 2> $NAME.err; then
	dgst_skip "$(cat $NAME.err)"
fi

# craf dgst <arguments> and openssl dgst with the same, but where craf
# goes beyond openssl: the same exit status, zero or not, and the same
# verdict on stdout; craf with <status>
verdict () {	# <status> <arguments>...
	local exp=$1 rc=0 orc=0
	shift
	craf dgst "$@" > $NAME.craf 2> $NAME.err < /dev/null || rc=$?
	openssl dgst "$@" > $NAME.ossl 2> /dev/null < /dev/null || orc=$?
	if [ $rc -ne $exp ] || [ $((rc != 0)) -ne $((orc != 0)) ] ||
		! cmp -s $NAME.craf $NAME.ossl; then
		echo "craf dgst $*: exit $rc, $(cat $NAME.err $NAME.craf); openssl: exit $orc, $(cat $NAME.ossl)"
		fail=y
	fi
}

# The forms of the key openssl takes: verified, a DER one with bytes after
# it too
openssl rsa -in $NAME.pem -RSAPublicKey_out -outform DER \
	-out $NAME.rsa.der 2> /dev/null
{
	cat $NAME.pub.der
	head -c 50 /dev/urandom
} > $NAME.tail.der
for key in $NAME.pub.pem $NAME.pub.der $NAME.rsa.pem $NAME.rsa.der \
	$NAME.tail.der; do
	verdict 0 -sha256 -verify $key -signature $NAME.sig $NAME.in
done
verdict 0 -verify $NAME.pub.pem -signature $NAME.sig $NAME.in
verdict 0 -sha384 -verify $NAME.pub.pem -signature $NAME.sig384 $NAME.in

# What does not hold: refused, as with openssl
cp $NAME.in $NAME.bad
flip $NAME.bad 5000
verdict 1 -sha256 -verify $NAME.pub.pem -signature $NAME.sig $NAME.bad
cp $NAME.sig $NAME.badsig
flip $NAME.badsig 100
verdict 1 -sha256 -verify $NAME.pub.pem -signature $NAME.badsig $NAME.in
head -c 255 $NAME.sig > $NAME.short
verdict 1 -sha256 -verify $NAME.pub.pem -signature $NAME.short $NAME.in
verdict 1 -sha384 -verify $NAME.pub.pem -signature $NAME.sig $NAME.in
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2> /dev/null |
	openssl pkey -pubout -out $NAME.other.pem
verdict 1 -sha256 -verify $NAME.other.pem -signature $NAME.sig $NAME.in

# As openssl: a signature file longer than the key's signatures is read
# for its first bytes, and an empty one is refused
cat $NAME.sig $NAME.sig > $NAME.long
verdict 0 -sha256 -verify $NAME.pub.pem -signature $NAME.long $NAME.in
: > $NAME.empty
rc=0
craf dgst -verify $NAME.pub.pem -signature $NAME.empty $NAME.in \
	> $NAME.craf 2> $NAME.err || rc=$?
if [ $rc -ne 1 ] || [ "$(cat $NAME.craf)" != "Verification failure" ] ||
	! grep -qxF 'craf: dgst: the signature file is empty' $NAME.err; then
	echo "craf dgst with an empty signature: exit $rc, $(cat $NAME.err $NAME.craf)"
	fail=y
fi

# The data from stdin
rc=0
craf dgst -verify $NAME.pub.pem -signature $NAME.sig < $NAME.in \
	> $NAME.craf 2> $NAME.err || rc=$?
if [ $rc -ne 0 ] || [ "$(cat $NAME.craf)" != "Verified OK" ]; then
	echo "craf dgst -verify < file: exit $rc, $(cat $NAME.err $NAME.craf)"
	fail=y
fi

# A certificate, which openssl does not take: its key verifies
dgst_expect 0 '' -verify $NAME.crt -signature $NAME.sig $NAME.in
if [ "$(cat $NAME.out)" != "Verified OK" ]; then
	echo "craf dgst -verify <certificate>: $(cat $NAME.err $NAME.out)"
	fail=y
fi

# -hex and -binary are taken, and said to have no effect
dgst_expect 0 'craf: warning: -hex and -binary have no effect when verifying' \
	-binary -verify $NAME.pub.pem -signature $NAME.sig $NAME.in

# -keyform, as openssl takes it: the format is craf's to tell, and one
# that does not match the file is said
for kf in "PEM $NAME.pub.pem" "der $NAME.pub.der"; do
	set -- $kf
	dgst_expect 0 '' -keyform $1 -verify $2 -signature $NAME.sig $NAME.in
	if [ -s $NAME.err ] || [ "$(cat $NAME.out)" != "Verified OK" ]; then
		echo "craf dgst -keyform $1 -verify $2: $(cat $NAME.err $NAME.out)"
		fail=y
	fi
done
dgst_expect 0 "craf: warning: -keyform DER, but $NAME.pub.pem is PEM, read as such" \
	-keyform DER -verify $NAME.pub.pem -signature $NAME.sig $NAME.in

# A weak hash and a short key are warned of, as openssl takes them
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 \
	-out $NAME.1024 2> /dev/null
openssl pkey -in $NAME.1024 -pubout -out $NAME.1024.pub
openssl dgst -sha1 -sign $NAME.1024 -out $NAME.sig1 $NAME.in
rc=0
craf dgst -sha1 -verify $NAME.1024.pub -signature $NAME.sig1 $NAME.in \
	> $NAME.craf 2> $NAME.err || rc=$?
if [ $rc -ne 0 ] || [ "$(cat $NAME.craf)" != "Verified OK" ] ||
	! grep -qxF 'craf: warning: sha1 is a weak hash for a signature' $NAME.err ||
	! grep -qxF 'craf: warning: the key has 1024 bits, fewer than 2048' $NAME.err; then
	echo "craf dgst -sha1 with a 1024-bit key: exit $rc, $(cat $NAME.err $NAME.craf)"
	fail=y
fi
if dgst_has md5 &&
	openssl dgst -md5 -sign $NAME.pem -out $NAME.sig5 $NAME.in 2> /dev/null; then
	dgst_expect 0 'craf: warning: md5 is a weak hash for a signature' \
		-md5 -verify $NAME.pub.pem -signature $NAME.sig5 $NAME.in
fi
rc=0
craf dgst -sha256 -verify $NAME.pub.pem -signature $NAME.sig $NAME.in \
	> /dev/null 2> $NAME.err || rc=$?
if [ $rc -ne 0 ] || [ -s $NAME.err ]; then
	echo "craf dgst -sha256 with a 2048-bit key: exit $rc, $(cat $NAME.err)"
	fail=y
fi

# What craf could not do, exit status 3
dgst_expect 3 "dgst: $NAME.pem: not a public key or a certificate" \
	-verify $NAME.pem -signature $NAME.sig $NAME.in
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2> /dev/null |
	openssl pkey -pubout -out $NAME.ec.pem
dgst_expect 3 "dgst: $NAME.ec.pem: not an RSA key" \
	-verify $NAME.ec.pem -signature $NAME.sig $NAME.in
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout /dev/null -subj /CN=$NAME-ec -days 1 -out $NAME.ec.crt 2> /dev/null
dgst_expect 3 'dgst: the key cannot be used with "enc=pkcs1 hash=sha256"' \
	-verify $NAME.ec.crt -signature $NAME.sig $NAME.in
flip $NAME.crt.der $(($(stat -c %s $NAME.crt.der) - 10))
dgst_expect 3 "dgst: cannot load the key of $NAME.crt.der (DER)" \
	-verify $NAME.crt.der -signature $NAME.sig $NAME.in
dgst_expect 3 "dgst: the key cannot be used with \"enc=pkcs1 hash=blake2b512\"" \
	-blake2b512 -verify $NAME.pub.pem -signature $NAME.sig $NAME.in
dgst_expect 3 "dgst: cannot open $NAME.nokey: No such file or directory" \
	-verify $NAME.nokey -signature $NAME.sig $NAME.in
dgst_expect 3 "dgst: cannot open $NAME.nosig: No such file or directory" \
	-verify $NAME.pub.pem -signature $NAME.nosig $NAME.in
dgst_expect 3 "dgst: cannot open $NAME.nofile: No such file or directory" \
	-verify $NAME.pub.pem -signature $NAME.sig $NAME.nofile
{
	printf '\x30\x82\x4e\x27\x02\x82\x4e\x20'
	head -c 20000 /dev/urandom
	printf '\x02\x01\x03'
} > $NAME.huge.der
dgst_expect 3 "dgst: $NAME.huge.der: an RSA key longer than 16384 bytes" \
	-verify $NAME.huge.der -signature $NAME.sig $NAME.in
mkdir $NAME.dir
dgst_expect 3 "dgst: cannot read $NAME.dir: Is a directory" \
	-verify $NAME.dir -signature $NAME.sig $NAME.in
dgst_expect 3 "dgst: cannot read $NAME.dir: Is a directory" \
	-verify $NAME.pub.pem -signature $NAME.dir $NAME.in
dgst_expect 3 "dgst: cannot read $NAME.dir: Is a directory" \
	-verify $NAME.pub.pem -signature $NAME.sig $NAME.dir

# An output that cannot be written: could not, but a refusal stays one
dgst_unwritable 3 'cannot write output' \
	-verify $NAME.pub.pem -signature $NAME.sig $NAME.in
dgst_unwritable 1 'dgst: verification failure' \
	-verify $NAME.pub.pem -signature $NAME.sig $NAME.bad

# Wrong usage, exit status 2
dgst_expect 2 'dgst: -signature needs a key to verify with' -signature $NAME.sig $NAME.in
dgst_expect 2 'dgst: -verify needs -signature' -verify $NAME.pub.pem $NAME.in
dgst_expect 2 'dgst: only one file can be verified, as with openssl' \
	-verify $NAME.pub.pem -signature $NAME.sig $NAME.in $NAME.in

. test-end.inc
