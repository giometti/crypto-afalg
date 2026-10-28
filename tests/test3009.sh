#!/bin/bash

echo -n "libkcrypto  [pkey-pubkey]: "

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

# The material, made by openssl, the oracle: RSA keys of two sizes, whose
# public keys need DER lengths of one and two bytes, and the SHA-256
# signatures of data
head -c 10000 /dev/urandom > $NAME.in
openssl dgst -sha256 -binary $NAME.in > $NAME.d256
for bits in 2048 4096; do
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$bits \
		-out $NAME-$bits.pem 2> /dev/null
	openssl pkey -in $NAME-$bits.pem -pubout -outform DER \
		-out $NAME-$bits.pub
	openssl dgst -sha256 -sign $NAME-$bits.pem -out $NAME-$bits.sig \
		$NAME.in
done
openssl req -x509 -new -key $NAME-2048.pem -subj /CN=$NAME -days 1 \
	-outform DER -out $NAME.cert 2> /dev/null

# A kernel without asymmetric keys or X.509 certificates skips the test,
# with its reason
if ! keyctl padd asymmetric "" @s < $NAME.cert > /dev/null 2> $NAME.err; then
	echo "Skipped ($(cat $NAME.err))"
	exit 0
fi

fail=n
p='enc=pkcs1 hash=sha256'

# The kernel loads a certificate that is not self-signed without checking
# its signature: what kc_key_pubkey() stands on. Here a certificate
# signed by another key, with its signature spoiled, verifies.
openssl req -x509 -new -key $NAME-4096.pem -subj /CN=$NAME-ca -days 1 \
	-out $NAME.ca 2> /dev/null
openssl req -new -key $NAME-2048.pem -subj /CN=$NAME-leaf \
	-out $NAME.csr 2> /dev/null
openssl x509 -req -in $NAME.csr -CA $NAME.ca -CAkey $NAME-4096.pem \
	-set_serial 2 -days 1 -outform DER -out $NAME.leaf 2> /dev/null
flip $NAME.leaf $(($(stat -c %s $NAME.leaf) - 10))
expect 0 - pkey-verify cert:$NAME.leaf "$p" $NAME.d256 $NAME-2048.sig

# The public keys of openssl verify its signatures, and refuse a digest
# that is not of the data
cp $NAME.d256 $NAME.bad
flip $NAME.bad 7
for bits in 2048 4096; do
	expect 0 - pkey-verify pubkey:$NAME-$bits.pub "$p" $NAME.d256 \
		$NAME-$bits.sig
	expect 1 'kc-check: status=1 errnum=129: verification failure: Key was rejected by service' \
		pkey-verify pubkey:$NAME-$bits.pub "$p" $NAME.bad \
		$NAME-$bits.sig
done

# What is not one DER SEQUENCE of its own length is a wrong argument,
# with a length of each form: one byte (an EC key), two (RSA 1024) and
# three (RSA 2048)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
	-out $NAME.ec 2> /dev/null
openssl pkey -in $NAME.ec -pubout -outform DER -out $NAME.ecpub
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 \
	-out $NAME-1024.pem 2> /dev/null
openssl pkey -in $NAME-1024.pem -pubout -outform DER -out $NAME-1024.pub
: > $NAME.empty
openssl pkey -in $NAME-2048.pem -pubout -out $NAME.pem 2> /dev/null
bad="$NAME.empty $NAME.pem $NAME.in"
for src in $NAME.ecpub $NAME-1024.pub $NAME-2048.pub; do
	head -c $(($(stat -c %s $src) - 1)) $src > $src.cut
	cat $src > $src.long
	printf '\000' >> $src.long
	bad="$bad $src.cut $src.long"
done
expect 0 - pkey-query pubkey:$NAME-1024.pub "$p"
for f in $bad; do
	expect 2 "kc-check: status=2 errnum=22: the public key is not one DER SEQUENCE of $(stat -c %s $f) bytes" \
		pkey-query pubkey:$f "$p"
done
head -c 16385 /dev/zero > $NAME.big
expect 2 'kc-check: status=2 errnum=7: public key too long' \
	pkey-query pubkey:$NAME.big "$p"

# A key that is not RSA: refused at the loading or at the query, a
# failure either way
rc=0
kc-check pkey-verify pubkey:$NAME.ecpub "$p" $NAME.d256 $NAME-2048.sig \
	2> $NAME.err || rc=$?
if [ $rc -ne 3 ]; then
	echo "kc-check pkey-verify with an EC key: exit $rc, $(cat $NAME.err)"
	fail=y
fi

. test-end.inc
