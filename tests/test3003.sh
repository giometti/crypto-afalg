#!/bin/bash

echo -n "libkcrypto  [cipher]: "

. test-preset.inc
. kc-test.inc

if ! test_cbc; then
	echo Skipped
	exit 0
fi

# usage: hex <hex string> <file>: the bytes
hex () {
	printf "$(printf %s "$1" | sed 's/../\\x&/g')" > "$2"
}

fail=n
key=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
key128=2b7e151628aed2a6abf7158809cf4f3c
iv=000102030405060708090a0b0c0d0e0f

# NIST SP 800-38A, F.2.5 CBC-AES256.Encrypt: the four blocks, then the
# block of padding PKCS#7 adds
hex 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710 \
	$NAME.in
hex f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b \
	$NAME.nist
kc-check cipher enc "$cbc" hex:$key $iv < $NAME.in > $NAME.out || fail=y
head -c 64 $NAME.out | cmp - $NAME.nist || fail=y
[ $(stat -c %s $NAME.out) -eq 80 ] || fail=y

# Every length, through updates of every size, against openssl
for size in 0 1 15 16 17 63 64 65 4096 5000 50000; do
	head -c $size /dev/urandom > $NAME.in
	openssl enc -aes-256-cbc -K $key -iv $iv < $NAME.in > $NAME.ref
	kc-check cipher enc "$cbc" hex:$key $iv < $NAME.in > $NAME.out ||
		fail=y
	cmp $NAME.ref $NAME.out || fail=y
	kc-check cipher dec "$cbc" hex:$key $iv < $NAME.ref > $NAME.out ||
		fail=y
	cmp $NAME.in $NAME.out || fail=y
	openssl enc -aes-128-cbc -K $key128 -iv $iv < $NAME.in > $NAME.ref
	kc-check cipher enc "$cbc" hex:$key128 $iv < $NAME.in > $NAME.out ||
		fail=y
	cmp $NAME.ref $NAME.out || fail=y
done

# A ciphertext refused: its length, and every way its padding is wrong
bad='kc-check: status=1 errnum=0: bad decrypt (wrong final block length)'
pad='kc-check: status=1 errnum=0: bad decrypt (wrong padding)'
head -c 5000 /dev/urandom > $NAME.in
openssl enc -aes-256-cbc -K $key -iv $iv < $NAME.in > $NAME.enc
head -c 4999 $NAME.enc > $NAME.trunc
: > $NAME.empty
for f in $NAME.trunc $NAME.empty; do
	kc-check cipher dec "$cbc" hex:$key $iv < $f > $NAME.out \
		2> $NAME.err && fail=y
	grep -qxF "$bad" $NAME.err || fail=y
	# Every whole block, as openssl writes it before refusing
	openssl enc -d -aes-256-cbc -K $key -iv $iv < $f > $NAME.ref \
		2> /dev/null && fail=y
	cmp $NAME.ref $NAME.out || fail=y
done
for last in 00 11 0203 01020303; do
	printf 'x%.0s' $(seq $((32 - ${#last} / 2))) > $NAME.plain
	hex $last $NAME.tail
	cat $NAME.tail >> $NAME.plain
	openssl enc -aes-256-cbc -nopad -K $key -iv $iv < $NAME.plain \
		> $NAME.enc
	kc-check cipher dec "$cbc" hex:$key $iv < $NAME.enc > /dev/null \
		2> $NAME.err && fail=y
	grep -qxF "$pad" $NAME.err || fail=y
done

# The wrong arguments, and what cannot be done
long=$(printf 'x%.0s' $(seq 64))
expect 2 'kc-check: status=2 errnum=22: a cipher needs a key' \
	cipher enc "$cbc" - $iv
expect 2 'kc-check: status=2 errnum=22: invalid IV length 0' \
	cipher enc "$cbc" hex:$key ''
expect 2 'kc-check: status=2 errnum=22: invalid IV length 33' \
	cipher enc "$cbc" hex:$key $(printf '00%.0s' $(seq 33))
expect 2 'kc-check: status=2 errnum=36: bind(): File name too long' \
	cipher enc "$long" hex:$key $iv
expect 1 'kc-check: status=1 errnum=2: bind(): No such file or directory' \
	cipher enc 'nosuch(aes)' hex:$key $iv
# A final ends the cipher, also when it fails
for dir in enc dec; do
	expect 2 'kc-check: status=2 errnum=22: the cipher cannot be used any more' \
		cipher-after $dir "$cbc" hex:$key $iv
done
expect 3 'kc-check: status=3 errnum=22: setsockopt(ALG_SET_KEY): Invalid argument' \
	cipher enc "$cbc" hex:0011 $iv
expect 3 'kc-check: status=3 errnum=22: sendmsg(): Invalid argument' \
	cipher enc "$cbc" hex:$key 0001020304050607

. test-end.inc
