#!/bin/bash

echo -n "libkcrypto  [blob-trusted]: "

. test-preset.inc
. kc-test.inc

if ! test_cbc || ! key_serial || ! keyctl new_session > /dev/null 2>&1; then
	echo Skipped
	exit 0
fi

# A trusted key, if the kernel has a trust source; CRAF_TEST_TRUSTED
# holds the options of "new" it needs, as for test2007, and given, it
# says the key can be made: then not making it is a failure
rc=0
tkey=$(keyctl add trusted $NAME-t "new 32 $CRAF_TEST_TRUSTED" @s \
	2> $NAME.err) || rc=$?
if [ $rc -ne 0 ]; then
	if [ -n "$CRAF_TEST_TRUSTED" ]; then
		echo "keyctl add trusted: $(cat $NAME.err)"
		echo KO!
		exit 1
	fi
	echo "Skipped ($(cat $NAME.err))"
	exit 0
fi

fail=n
iv=000102030405060708090a0b0c0d0e0f
blob=$(keyctl pipe $tkey)

# The blob loads the key the kernel made: the same cipher as by serial
head -c 5000 /dev/urandom > $NAME.in
kc-check cipher enc "$cbc" spec:$tkey $iv < $NAME.in > $NAME.ref || fail=y
kc-check cipher enc "$cbc" blob:$blob $iv < $NAME.in > $NAME.out || fail=y
cmp $NAME.ref $NAME.out || fail=y

# Two keys of one thread, of the same blob too, live side by side
expect 0 - blob-twice $blob

# Unloaded, the key is out of the keyring, and a second unload has
# nothing to do; one gone already is a failure to say
rc=0
kc-check blob-unload $blob "$cbc" 2> $NAME.err || rc=$?
if [ $rc -ne 3 ] || ! grep -qx 'kc-check: status=3 errnum=126: key [0-9]*: Required key not available' \
	$NAME.err; then
	echo "kc-check blob-unload: exit $rc, $(cat $NAME.err)"
	fail=y
fi
rc=0
kc-check blob-gone $blob 2> $NAME.err || rc=$?
if [ $rc -ne 3 ] || ! grep -qx 'kc-check: status=3 errnum=126: cannot remove the key [0-9]*: Required key not available' \
	$NAME.err; then
	echo "kc-check blob-gone: exit $rc, $(cat $NAME.err)"
	fail=y
fi

. test-end.inc
