#!/bin/bash

echo -n "keyserial   [spec]: "

. test-preset.inc

# crypto-afalg offers -S exactly when the library takes keyring keys; the
# help is captured first: grep -q on a pipe can make it fail by SIGPIPE
fail=n
for cmd in encrypt hash; do
	crypto-afalg $cmd -h > $NAME.help 2>&1 || true
	if grep -q keyserial $NAME.help; then
		key_serial || fail=y
	elif key_serial; then
		fail=y
	fi
done
if ! key_serial; then
	echo -n "(no keyring keys) "
	. test-end.inc
fi
if ! keyctl new_session > /dev/null 2>&1; then
	echo Skipped
	exit 0
fi

head -c 32 /dev/urandom > $NAME.key
key=$(od -An -tx1 -v $NAME.key | tr -d ' \n')
id=$(keyctl padd user $NAME @s < $NAME.key)
echo -n 'Single block msgSecond block msg' > $NAME.in
openssl dgst -sha256 -mac HMAC -macopt hexkey:$key < $NAME.in |
	sed 's/^.*= //' > $NAME.ref

# A key by serial and by description, with both names of the keyring
for spec in $id @s,user,$NAME session,user,$NAME; do
	crypto-afalg hash hmac-sha-256 -S $spec < $NAME.in > $NAME.out || fail=y
	diff -u $NAME.ref $NAME.out || fail=y
done

# Why a spec is refused: exit status 1 and one line of reason
refused () {
	rc=0
	crypto-afalg hash hmac-sha-256 -S "$1" < $NAME.in \
		> /dev/null 2> $NAME.err || rc=$?
	if [ $rc -ne 1 ] || ! grep -qxF -e "crypto-afalg: $2" $NAME.err; then
		echo "-S $1: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
}

# A serial is decimal digits only, positive and within 32 bits
for spec in 0 ${id}abc " $id" +$id -3 2147483648 $((id + 4294967296)); do
	refused "$spec" "invalid key serial number \"$spec\""
done

# A keyring is named exactly, and the type and the description are given
for ring in s @ '' foo; do
	refused "$ring,user,$NAME" "unknown keyring name \"$ring\""
done
refused "@s,,$NAME" "empty key type in \"@s,,$NAME\""
refused @s,user, 'empty key description in "@s,user,"'
refused @s,user,$NAME-missing \
	"cannot get ID for user key $NAME-missing in keyring @s: Required key not available"

# A description held twice, here through a keyring linked to @s
ring=$(keyctl newring $NAME-ring @s)
keyctl padd user $NAME $ring < $NAME.key > /dev/null
refused @s,user,$NAME "more than one user key $NAME in keyring @s"

. test-end.inc
