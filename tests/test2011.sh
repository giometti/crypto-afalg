#!/bin/bash

echo -n "craf        [enc-usage]: "

. test-preset.inc
. enc-test.inc

fail=n
printf 'secret\n' > $NAME.key
head -c 100 /dev/urandom > $NAME.in
openssl enc -e -aes-256-cbc -pbkdf2 -kfile $NAME.key < $NAME.in > $NAME.enc
ok=(-aes-256-cbc -pbkdf2 -kfile $NAME.key)

# Wrong usage, exit status 2
enc_expect 2 'craf encrypts only with -enc-key, give -d' $NAME.enc "${ok[@]}"
enc_expect 2 'craf encrypts only with -enc-key, give -d' $NAME.enc -d -e \
	"${ok[@]}"
enc_expect 2 'enc: -iv is for -enc-key' $NAME.enc -d "${ok[@]}" -iv 00
enc_expect 2 'a cipher is required' $NAME.enc -d -pbkdf2 -kfile $NAME.key
enc_expect 2 'give -aes-256-cbc or -cipher-algo, not both' $NAME.enc -d \
	"${ok[@]}" -cipher-algo 'cbc(aes)'
enc_expect 2 '-cipher-key-len is for -cipher-algo' $NAME.enc -d \
	"${ok[@]}" -cipher-key-len 32
enc_expect 2 'only -pbkdf2 (or -iter) is supported' $NAME.enc -d \
	-aes-256-cbc -kfile $NAME.key
enc_expect 2 'a passphrase is required' $NAME.enc -d -aes-256-cbc -pbkdf2
enc_expect 2 '-iter: "0" is not a count of 1 or more' $NAME.enc -d \
	"${ok[@]}" -iter 0
enc_expect 2 '-cipher-key-len: "65" is not 1 to 64' $NAME.enc -d \
	-cipher-algo 'cbc(aes)' -cipher-key-len 65 -pbkdf2 -kfile $NAME.key
for opt in -a -nosalt -nopad -p -P -v -none -z '-K 00' '-S 00'; do
	enc_expect 2 "enc: ${opt%% *} is not supported by craf" $NAME.enc \
		-d "${ok[@]}" $opt
done
for mode in aes-256-gcm aes-128-ccm aes-128-ocb aes-256-siv aes-256-gcm-siv \
	chacha20-poly1305 aes-256-xts aes-256-wrap aes-256-wrap-pad; do
	enc_expect 2 "the format of openssl enc has no room for -$mode" \
		$NAME.enc -d -$mode -pbkdf2 -kfile $NAME.key
done
for algo in 'xts(aes)' 'gcm(aes)' 'kw(aes)' 'rfc4106(gcm(aes))'; do
	enc_expect 2 "the format of openssl enc has no room for $algo" \
		$NAME.enc -d -cipher-algo "$algo" -pbkdf2 -kfile $NAME.key
done
for word in -cipher-drive -pbk -iterations -in-file -aes256 -AES-256-CBC; do
	enc_expect 2 "unknown option or missing value \"$word\"" $NAME.enc -d \
		"${ok[@]}" $word
done
enc_expect 2 'give -cipher-key-len, cbc(aes) takes 16 to 32 bytes' \
	$NAME.enc -d -cipher-algo 'cbc(aes)' -pbkdf2 -kfile $NAME.key
enc_expect 2 'a 64-byte key is not one cbc(aes) takes, 16 to 32 bytes' \
	$NAME.enc -d -aes-512-cbc -pbkdf2 -kfile $NAME.key
: > $NAME.empty
printf '\n' > $NAME.nl
enc_expect 2 '-kfile: no passphrase in it' $NAME.enc -d -aes-256-cbc \
	-pbkdf2 -kfile $NAME.empty
enc_expect 2 '-kfile: an empty passphrase' $NAME.enc -d -aes-256-cbc \
	-pbkdf2 -kfile $NAME.nl
enc_expect 2 '-pass: no passphrase in it' $NAME.enc -d -aes-256-cbc \
	-pbkdf2 -pass file:$NAME.empty
enc_expect 2 '-pass: no variable ENC_TEST_NONE in the environment' \
	$NAME.enc -d -aes-256-cbc -pbkdf2 -pass env:ENC_TEST_NONE
enc_expect 2 '-pass: "stdin" is not supported' $NAME.enc -d -aes-256-cbc \
	-pbkdf2 -pass stdin
enc_expect 2 '-pass: "x" is not a descriptor' $NAME.enc -d -aes-256-cbc \
	-pbkdf2 -pass fd:x
enc_expect 2 '-pass: descriptor 0 is the input' $NAME.enc -d -aes-256-cbc \
	-pbkdf2 -pass fd:0
# A source mistyped may be the passphrase: it is not repeated
enc_expect 2 '-pass: a source is required' $NAME.enc -d -aes-256-cbc \
	-pbkdf2 -pass sEcReT
grep -q sEcReT $NAME.err && fail=y
enc_expect 2 '-pass: "sEcReT:" is not supported' $NAME.enc -d -aes-256-cbc \
	-pbkdf2 -pass sEcReT:more
grep -q more $NAME.err && fail=y

# The file of the passphrase is never the output, which is truncated
# before the passphrase is read
cp $NAME.key $NAME.out
enc_expect 2 'the output and the -kfile file are the same file' $NAME.enc \
	-d -aes-256-cbc -pbkdf2 -kfile $NAME.key -out $NAME.out -kfile $NAME.out
enc_expect 2 'the output and the -pass file are the same file' $NAME.enc \
	-d -aes-256-cbc -pbkdf2 -pass file:$NAME.out -out $NAME.out
exec 3< $NAME.out
enc_expect 2 'the output and the -pass file are the same file' $NAME.enc \
	-d -aes-256-cbc -pbkdf2 -pass fd:3 -out $NAME.out
exec 3<&-
cmp $NAME.key $NAME.out || fail=y
enc_expect 2 '-cipher-driver: the length must be 1 to 63' $NAME.enc -d \
	"${ok[@]}" -cipher-driver $(printf 'x%.0s' {1..64})
enc_expect 2 'names an algorithm, not a driver' $NAME.enc -d "${ok[@]}" \
	-cipher-driver 'cbc(aes)'
enc_expect 2 'unexpected argument "extra"' $NAME.enc -d "${ok[@]}" extra
long=$(printf 'x%.0s' {1..64})
enc_expect 2 '-cipher-algo: the length must be 1 to 63' $NAME.enc -d \
	-cipher-algo "cbc($long)" -pbkdf2 -kfile $NAME.key
enc_expect 2 "-$long-cbc gives a kernel name longer than 63 characters" \
	$NAME.enc -d -$long-cbc -pbkdf2 -kfile $NAME.key
enc_expect 2 '-md: the length must be 1 to 57' $NAME.enc -d "${ok[@]}" \
	-md ${long:6}
driver=$(kc-check driver-for-algo skcipher 'cbc(aes)' 2> /dev/null) || fail=y
enc_expect 2 "-cipher-algo \"$driver\" is a driver of cbc(aes): give it with -cipher-driver" \
	$NAME.enc -d \
	-cipher-algo "$driver" -cipher-key-len 32 -pbkdf2 -kfile $NAME.key
if kc-check available skcipher 'cbc(cast5)' 2> /dev/null; then
	enc_expect 2 "give -cipher-algo 'cbc(cast5)' -cipher-key-len" \
		$NAME.enc -d -cast5-cbc -pbkdf2 -kfile $NAME.key
fi

# What could not be done, exit status 3: a mode the kernel does not
# have, one craf does not run yet, a hash the kernel does not have
for algo in 'cfb(aes)' 'ofb(aes)' 'ecb(aes)' 'ctr(aes)' 'cts(cbc(aes))'; do
	rc=0
	kc-check available skcipher "$algo" 2> /dev/null || rc=$?
	if [ $rc -eq 0 ]; then
		enc_expect 3 "craf does not run $algo yet" $NAME.enc -d \
			-cipher-algo "$algo" -cipher-key-len 32 -pbkdf2 \
			-kfile $NAME.key
	else
		enc_expect 3 "($algo) not available: No such file or directory" \
			$NAME.enc -d -cipher-algo "$algo" -cipher-key-len 32 \
			-pbkdf2 -kfile $NAME.key
	fi
done
enc_expect 3 'enc: cipher aes-256-nosuch (nosuch(aes)) not available' \
	$NAME.enc -d -aes-256-nosuch -pbkdf2 -kfile $NAME.key
enc_expect 3 'enc: -md blake2b512: hmac(blake2b512) not available' \
	$NAME.enc -d "${drv[@]}" "${ok[@]}" -md blake2b512
enc_expect 3 '-cipher-driver "no-such-driver" not available' \
	$NAME.enc -d "${ok[@]}" -cipher-driver no-such-driver
enc_expect 3 '-kfile: cannot open' $NAME.enc -d -aes-256-cbc -pbkdf2 \
	-kfile $NAME.missing
# A descriptor that is not open is told before craf opens files of its
# own, one of which would take its number
rc=0
craf enc -d -aes-256-cbc -pbkdf2 -pass fd:3 -in $NAME.enc 3<&- \
	> /dev/null 2> $NAME.err || rc=$?
if [ $rc -ne 3 ] ||
	! grep -qF -e '-pass: cannot read descriptor 3' $NAME.err; then
	echo "craf enc -pass fd:3 closed: exit $rc, $(cat $NAME.err)"
	fail=y
fi
enc_expect 3 'cannot open' $NAME.enc -d "${ok[@]}" -in $NAME.missing

# The help, also for enc
craf enc -help > $NAME.out || fail=y
grep -q '^  enc -d' $NAME.out || fail=y

. test-end.inc
