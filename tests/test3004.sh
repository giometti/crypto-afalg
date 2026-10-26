#!/bin/bash

echo -n "libkcrypto  [pbkdf2-openssl]: "

. test-preset.inc
. kc-test.inc

if ! check-kalgo hash 'hmac(sha256)'; then
	echo Skipped
	exit 0
fi

# usage: tohex <string>: its bytes in hex
tohex () {
	printf %s "$1" | od -An -tx1 -v | tr -d ' \n'
}

fail=n

# RFC 7914, section 11: PBKDF2-HMAC-SHA256
kc-check pbkdf2 'hmac(sha256)' $(tohex passwd) $(tohex salt) 1 64 \
	> $NAME.out || fail=y
echo 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783 |
	cmp - $NAME.out || fail=y
kc-check pbkdf2 'hmac(sha256)' $(tohex Password) $(tohex NaCl) 80000 64 \
	> $NAME.out || fail=y
echo 4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d |
	cmp - $NAME.out || fail=y

# Key and IV as openssl enc -pbkdf2 derives them, its defaults
pass=$(head -c 12 /dev/urandom | od -An -tx1 -v | tr -d ' \n')
salt=$(head -c 8 /dev/urandom | od -An -tx1 -v | tr -d ' \n')
openssl enc -aes-256-cbc -pbkdf2 -pass pass:$pass -S $salt -P > $NAME.p
key=$(sed -n 's/^key=//p' $NAME.p)
iv=$(sed -n 's/^iv *=//p' $NAME.p)
kc-check pbkdf2 'hmac(sha256)' $(tohex $pass) $salt 10000 48 \
	> $NAME.out || fail=y
echo $key$iv | tr A-F a-f | cmp - $NAME.out || fail=y

# Key and IV of each length, as openssl derives them: the IV printed, the
# key used on a file of openssl, where the kernel has the cipher
for c in aes-128-cbc:16:16:'cbc(aes)' aes-192-cbc:24:16:'cbc(aes)' \
	aes-256-cbc:32:16:'cbc(aes)' des-ede3-cbc:24:8:'cbc(des3_ede)'; do
	IFS=: read name klen ilen kname <<< "$c"
	openssl enc -$name -pbkdf2 -iter 1000 -pass pass:$pass -S $salt -P \
		> $NAME.p
	iv=$(sed -n 's/^iv *=//p' $NAME.p | tr A-F a-f)
	kc-check derive 'hmac(sha256)' $(tohex $pass) $salt 1000 $klen $ilen \
		> $NAME.out || fail=y
	echo $iv | cmp - $NAME.out || fail=y
	kc-check available skcipher "$kname" 2> /dev/null || continue
	head -c 1000 /dev/urandom > $NAME.in
	openssl enc -$name -pbkdf2 -iter 1000 -pass pass:$pass < $NAME.in \
		> $NAME.enc
	kc-check openssl-dec "$kname" $(tohex $pass) 1000 $klen $ilen \
		< $NAME.enc > $NAME.out || fail=y
	cmp $NAME.in $NAME.out || fail=y
done
expect 2 'kc-check: status=2 errnum=22: invalid key length 0' \
	derive 'hmac(sha256)' 00 $salt 1 0 16
expect 2 'kc-check: status=2 errnum=22: invalid key length 65' \
	derive 'hmac(sha256)' 00 $salt 1 65 16
expect 2 'kc-check: status=2 errnum=22: invalid IV length 33' \
	derive 'hmac(sha256)' 00 $salt 1 32 33
expect 2 'kc-check: status=2 errnum=22: PBKDF2 needs one iteration at least' \
	derive 'hmac(sha256)' 00 $salt 0 32 16
expect 1 'kc-check: status=1 errnum=2: bind(): No such file or directory' \
	derive 'hmac(nosuch)' 00 $salt 1 32 16
expect 0 - derive 'hmac(sha256)' 00 $salt 1 32 0

# The header: read from openssl's output, and as openssl writes it
seq 1 100 | openssl enc -aes-256-cbc -pbkdf2 -pass pass:$pass > $NAME.enc
tail -c +9 $NAME.enc | head -c 8 | od -An -tx1 -v | tr -d ' \n' > $NAME.ref
echo >> $NAME.ref
kc-check header < $NAME.enc > $NAME.out || fail=y
cmp $NAME.ref $NAME.out || fail=y
kc-check header-make $(cat $NAME.ref) > $NAME.out || fail=y
head -c 16 $NAME.enc | cmp - $NAME.out || fail=y

# The wrong arguments, the refused data and what cannot be done
expect 2 'kc-check: status=2 errnum=22: PBKDF2 needs one iteration at least' \
	pbkdf2 'hmac(sha256)' 00 00 0 32
expect 2 'kc-check: status=2 errnum=22: PBKDF2 needs one byte of output at least' \
	pbkdf2 'hmac(sha256)' 00 00 1 0
expect 1 'kc-check: status=1 errnum=2: bind(): No such file or directory' \
	pbkdf2 'hmac(nosuch)' 00 00 1 32
expect 3 'kc-check: status=3 errnum=38: setsockopt(ALG_SET_KEY): Function not implemented' \
	pbkdf2 sha256 00 00 1 32
for len in 0 15; do
	head -c $len $NAME.enc > $NAME.short
	kc-check header < $NAME.short > /dev/null 2> $NAME.err && fail=y
	grep -qxF "kc-check: status=1 errnum=0: truncated openssl enc header ($len bytes)" \
		$NAME.err || fail=y
done
for magic in Seasoned Salted_X; do
	printf '%s01234567' $magic > $NAME.plain
	kc-check header < $NAME.plain > /dev/null 2> $NAME.err && fail=y
	grep -qxF 'kc-check: status=1 errnum=0: no "Salted__" header' \
		$NAME.err || fail=y
done

. test-end.inc
