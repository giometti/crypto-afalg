#!/bin/bash

echo -n "craf        [enc-openssl]: "

. test-preset.inc
. enc-test.inc

fail=n
printf 'secret\n' > $NAME.key

# Every length around the block and the 8192 bytes read at once, as
# craf enc -d reads them: the output is what openssl encrypted
for size in 0 1 15 16 17 4112 8191 8192 8193 1048583; do
	head -c $size /dev/urandom > $NAME.in
	openssl enc -e -aes-256-cbc -pbkdf2 -kfile $NAME.key \
		< $NAME.in > $NAME.enc
	craf enc -d "${drv[@]}" -in $NAME.enc -aes-256-cbc -pbkdf2 \
		-kfile $NAME.key > $NAME.out 2> $NAME.err || fail=y
	cmp $NAME.in $NAME.out || fail=y
	grep -qxF 'craf: warning: -aes-256-cbc taken as cbc(aes) with a 32-byte key' \
		$NAME.err || fail=y
done

# The other key lengths, the name of craf, and a cipher whose kernel
# name the table gives
head -c 5000 /dev/urandom > $NAME.in
for bits in 128 192; do
	openssl enc -e -aes-$bits-cbc -pbkdf2 -kfile $NAME.key \
		< $NAME.in > $NAME.enc
	craf enc -d "${drv[@]}" -aes-$bits-cbc -pbkdf2 -kfile $NAME.key \
		< $NAME.enc > $NAME.out 2> /dev/null || fail=y
	cmp $NAME.in $NAME.out || fail=y
	craf enc -d "${drv[@]}" -cipher-algo 'cbc(aes)' \
		-cipher-key-len $((bits / 8)) -pbkdf2 -kfile $NAME.key \
		< $NAME.enc > $NAME.out 2> $NAME.err || fail=y
	cmp $NAME.in $NAME.out || fail=y
	[ -s $NAME.err ] && fail=y
done
if kc-check available skcipher 'cbc(des3_ede)' 2> /dev/null; then
	openssl enc -e -des-ede3-cbc -pbkdf2 -kfile $NAME.key \
		< $NAME.in > $NAME.enc
	craf enc -d -des-ede3-cbc -pbkdf2 -kfile $NAME.key \
		< $NAME.enc > $NAME.out 2> $NAME.err || fail=y
	cmp $NAME.in $NAME.out || fail=y
	grep -qxF 'craf: warning: -des-ede3-cbc taken as cbc(des3_ede) with a 24-byte key' \
		$NAME.err || fail=y
else
	echo -n "(no cbc(des3_ede)) "
fi

# The iterations, the hash, and every source of the passphrase
openssl enc -e -aes-256-cbc -iter 1234 -md sha256 -pass pass:secret \
	< $NAME.in > $NAME.enc
pass_ok () {	# <arguments>...
	craf enc -d "${drv[@]}" -aes-256-cbc -iter 1234 "$@" \
		< $NAME.enc > $NAME.out 2> /dev/null || fail=y
	cmp $NAME.in $NAME.out || fail=y
}
pass_ok -md sha256 -kfile $NAME.key
printf 'secret' > $NAME.nonl
pass_ok -kfile $NAME.nonl
printf 'secret\r\n' > $NAME.crlf
pass_ok -kfile $NAME.crlf
pass_ok -k secret
pass_ok -pass pass:secret
pass_ok -pass file:$NAME.key
export ENC_TEST_PASS=secret
pass_ok -pass env:ENC_TEST_PASS
pass_ok -pass fd:3 3< $NAME.key
# As openssl: the last of -k and -kfile wins, over -pass whatever the
# order, and the last -pass wins when there is no other
pass_ok -k wrong -kfile $NAME.key
pass_ok -pass pass:wrong -k wrong -k secret
pass_ok -kfile $NAME.key -pass pass:wrong
pass_ok -k secret -pass file:$NAME.crlf
pass_ok -pass pass:wrong -pass pass:secret
openssl enc -d -aes-256-cbc -iter 1234 -kfile $NAME.key -pass pass:wrong \
	< $NAME.enc > $NAME.out 2> /dev/null || fail=y
cmp $NAME.in $NAME.out || fail=y
# The hash also by the name of a driver of it
md=$(kc-check driver-for-algo hash sha256 2> /dev/null) || fail=y
pass_ok -md "$md" -k secret

# -iter also in octal and in hex, as openssl reads it
openssl enc -e -aes-256-cbc -iter 4096 -pass pass:secret \
	< $NAME.in > $NAME.enc
for iter in 4096 010000 0x1000; do
	craf enc -d "${drv[@]}" -aes-256-cbc -iter $iter -k secret \
		< $NAME.enc > $NAME.out 2> /dev/null || fail=y
	cmp $NAME.in $NAME.out || fail=y
done

# -pass file: keeps a \r, as openssl does
openssl enc -e -aes-256-cbc -iter 1234 -pass file:$NAME.crlf \
	< $NAME.in > $NAME.enc
pass_ok -pass file:$NAME.crlf

# The lengths openssl reads of a long line: 127 of -kfile, 1023 of file:
printf 'p%.0s' $(seq 2000) > $NAME.long
echo >> $NAME.long
for opt in -kfile -pass; do
	if [ $opt = -kfile ]; then
		max=127 arg=$NAME.long
	else
		max=1023 arg=file:$NAME.long
	fi
	openssl enc -e -aes-256-cbc -pbkdf2 -pass pass:$(head -c $max $NAME.long) \
		< $NAME.in > $NAME.enc
	craf enc -d "${drv[@]}" -aes-256-cbc -pbkdf2 $opt $arg \
		< $NAME.enc > $NAME.out 2> $NAME.err || fail=y
	cmp $NAME.in $NAME.out || fail=y
	grep -qF "the passphrase is cut to $max characters, as openssl does" \
		$NAME.err || fail=y
done
# After the 127 characters of -kfile, a \r\n ends the line and cuts
# nothing; a \r followed by more cuts it
openssl enc -e -aes-256-cbc -pbkdf2 -pass pass:$(head -c 127 $NAME.long) \
	< $NAME.in > $NAME.enc
for end in '\r\n:n' '\rmore\n:y'; do
	{
		head -c 127 $NAME.long
		printf "${end%:*}"
	} > $NAME.cr
	craf enc -d "${drv[@]}" -aes-256-cbc -pbkdf2 -kfile $NAME.cr \
		< $NAME.enc > $NAME.out 2> $NAME.err || fail=y
	cmp $NAME.in $NAME.out || fail=y
	cut=n
	if grep -qF 'the passphrase is cut' $NAME.err; then
		cut=y
	fi
	[ $cut = ${end##*:} ] || fail=y
done

# -in, -out, and -salt with its warning
openssl enc -e -aes-256-cbc -pbkdf2 -kfile $NAME.key < $NAME.in > $NAME.enc
rm -f $NAME.out
craf enc -d "${drv[@]}" -salt -in $NAME.enc -out $NAME.out -aes-256-cbc \
	-pbkdf2 -kfile $NAME.key 2> $NAME.err || fail=y
cmp $NAME.in $NAME.out || fail=y
grep -qxF 'craf: warning: -salt has no effect when decrypting' \
	$NAME.err || fail=y

. test-end.inc
