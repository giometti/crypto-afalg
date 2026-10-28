#!/bin/bash

echo -n "libkcrypto  [pkey-cert]: "

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

# The material, made by openssl, the oracle: an RSA key, its self-signed
# certificate, data and their SHA-256 signature
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
	-out $NAME.pem 2> /dev/null
openssl req -x509 -new -key $NAME.pem -subj /CN=$NAME -days 1 \
	-outform DER -out $NAME.cert 2> /dev/null
head -c 10000 /dev/urandom > $NAME.in
openssl dgst -sha256 -sign $NAME.pem -out $NAME.sig $NAME.in
openssl dgst -sha256 -binary $NAME.in > $NAME.d256
openssl dgst -sha384 -binary $NAME.in > $NAME.d384

# A kernel without asymmetric keys or X.509 certificates skips the test,
# with its reason
if ! keyctl padd asymmetric "" @s < $NAME.cert > /dev/null 2> $NAME.err; then
	echo "Skipped ($(cat $NAME.err))"
	exit 0
fi

fail=n
cert=cert:$NAME.cert
p='enc=pkcs1 hash=sha256'

# usage: expect_re <status> <regex of the stderr line> <kc-check args...>
expect_re () {
	local want=$1 re=$2 rc=0

	shift 2
	kc-check "$@" < /dev/null > $NAME.got 2> $NAME.err || rc=$?
	if [ $rc -ne $want ] || ! grep -qx -e "$re" $NAME.err; then
		echo "kc-check $*: exit $rc, not $want: $(cat $NAME.err)"
		fail=y
	fi
}

# The query: an RSA key of 2048 bits that verifies
expect 0 - pkey-query $cert "$p"
read -r ops bits max_data max_sig max_enc max_dec reserved < $NAME.got
if [ $((ops & 8)) -eq 0 ] || [ "$bits" != 2048 ] || [ "$reserved" != 0 ]; then
	echo "pkey-query: $(cat $NAME.got)"
	fail=y
fi

# The signature of openssl holds
expect 0 - pkey-verify $cert "$p" $NAME.d256 $NAME.sig

# What the kernel refuses is a "no": the digest, the signature, a digest
# of another hash; a longer signature is refused before the kernel
no='kc-check: status=1 errnum=[0-9]*: verification failure: .*'
cp $NAME.d256 $NAME.bad
flip $NAME.bad 7
expect_re 1 "$no" pkey-verify $cert "$p" $NAME.bad $NAME.sig
cp $NAME.sig $NAME.bad
flip $NAME.bad 100
expect_re 1 "$no" pkey-verify $cert "$p" $NAME.d256 $NAME.bad
head -c $((max_sig - 1)) $NAME.sig > $NAME.bad
expect_re 1 "$no" pkey-verify $cert "$p" $NAME.d256 $NAME.bad
expect_re 1 "$no" pkey-verify $cert 'enc=pkcs1 hash=sha384' \
	$NAME.d384 $NAME.sig
cat $NAME.sig $NAME.sig | head -c $((max_sig + 1)) > $NAME.bad
expect 1 "kc-check: status=1 errnum=0: verification failure: a signature of $((max_sig + 1)) bytes, the key's are at most $max_sig" \
	pkey-verify $cert "$p" $NAME.d256 $NAME.bad

# Parameters the kernel does not take are a failure, at the query, not a
# forged signature
for q in 'enc=pkcs1 hash=nosuchhash' 'enc=nosuchenc hash=sha256'; do
	expect_re 3 "kc-check: status=3 errnum=[0-9]*: cannot query the key [0-9]* with \"$q\": .*" \
		pkey-verify $cert "$q" $NAME.d256 $NAME.sig
done

# Lengths and keys that cannot be: wrong arguments
: > $NAME.empty
expect_re 2 "kc-check: status=2 errnum=22: a digest of 0 bytes, the key takes 1 to $max_data" \
	pkey-verify $cert "$p" $NAME.empty $NAME.sig
head -c $((max_data + 1)) $NAME.in > $NAME.bad
expect_re 2 "kc-check: status=2 errnum=22: a digest of $((max_data + 1)) bytes, the key takes 1 to $max_data" \
	pkey-verify $cert "$p" $NAME.bad $NAME.sig
expect 2 'kc-check: status=2 errnum=22: empty signature' \
	pkey-verify $cert "$p" $NAME.d256 $NAME.empty
expect 2 'kc-check: status=2 errnum=22: not a keyring key' \
	pkey-verify hex:00 "$p" $NAME.d256 $NAME.sig
expect 2 'kc-check: status=2 errnum=22: no parameters' pkey-query $cert -
expect 2 'kc-check: status=2 errnum=22: no parameters' \
	pkey-verify $cert - $NAME.d256 $NAME.sig
expect 2 'kc-check: status=2 errnum=22: empty certificate' \
	pkey-query cert:$NAME.empty "$p"

# A key that is not asymmetric, and what the kernel does not load
id=$(keyctl padd user $NAME @s < $NAME.d256)
expect_re 3 "kc-check: status=3 errnum=[0-9]*: cannot query the key $id with \"$p\": .*" \
	pkey-query spec:$id "$p"
expect_re 3 'kc-check: status=3 errnum=[0-9]*: cannot load the certificate: .*' \
	pkey-query cert:$NAME.in "$p"

# A self-signed certificate whose signature does not hold is refused
cp $NAME.cert $NAME.bad
flip $NAME.bad $(($(stat -c %s $NAME.bad) - 10))
expect_re 3 'kc-check: status=3 errnum=[0-9]*: cannot load the certificate: .*' \
	pkey-query cert:$NAME.bad "$p"

# A key that is not RSA cannot be used with these parameters: refused at
# the loading or at the query, a failure either way
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	-nodes -keyout $NAME.ec -subj /CN=$NAME-ec -days 1 -outform DER \
	-out $NAME.ecc 2> /dev/null
expect_re 3 'kc-check: status=3 errnum=[0-9]*: .*' \
	pkey-verify cert:$NAME.ecc "$p" $NAME.d256 $NAME.sig

. test-end.inc
