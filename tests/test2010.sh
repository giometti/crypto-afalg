#!/bin/bash

echo -n "craf        [enc-refused]: "

. test-preset.inc
. enc-test.inc

fail=n
printf 'secret\n' > $NAME.key
head -c 5000 /dev/urandom > $NAME.in
openssl enc -e -aes-256-cbc -pbkdf2 -kfile $NAME.key < $NAME.in > $NAME.good
size=$(stat -c %s $NAME.good)

# craf writes what openssl writes before it refuses a file, with exit
# status 1 and the reason on the last line
same_as_openssl () {	# <reason> <arguments of the passphrase>...
	local reason=$1 rc=0
	shift
	openssl enc -d -aes-256-cbc -pbkdf2 "$@" < $NAME.enc > $NAME.ref \
		2> /dev/null && fail=y
	craf enc -d "${drv[@]}" -aes-256-cbc -pbkdf2 "$@" < $NAME.enc \
		> $NAME.out 2> $NAME.err || rc=$?
	if [ $rc -ne 1 ] || ! cmp -s $NAME.ref $NAME.out ||
		! grep -qF -e "$reason" <<< "$(tail -n 1 $NAME.err)"; then
		echo "$reason: exit $rc, $(wc -c < $NAME.ref) bytes from openssl, $(wc -c < $NAME.out) from craf, $(tail -n 1 $NAME.err)"
		fail=y
	fi
}

# A wrong passphrase: every block but the last, a wrong padding. With a
# random salt the last block is a valid padding about once in 256: encrypt
# again until openssl refuses it
for try in 1 2 3 4; do
	openssl enc -e -aes-256-cbc -pbkdf2 -kfile $NAME.key \
		< $NAME.in > $NAME.enc
	openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:wrong \
		< $NAME.enc > /dev/null 2>&1 || break
done
same_as_openssl 'bad decrypt (wrong padding)' -pass pass:wrong

# Cut inside the data, or after the header: every whole block
for cut in 1 15 17; do
	head -c $((size - cut)) $NAME.good > $NAME.enc
	same_as_openssl 'bad decrypt (wrong final block length)' -kfile $NAME.key
done
head -c 16 $NAME.good > $NAME.enc
same_as_openssl 'bad decrypt (wrong final block length)' -kfile $NAME.key

# Cut inside the header, or no header at all: nothing goes out
for len in 0 15; do
	head -c $len $NAME.good > $NAME.enc
	same_as_openssl "truncated openssl enc header ($len bytes)" \
		-kfile $NAME.key
done
openssl enc -e -aes-256-cbc -pbkdf2 -nosalt -kfile $NAME.key \
	< $NAME.in > $NAME.enc
same_as_openssl 'no "Salted__" header' -kfile $NAME.key

. test-end.inc
