#!/bin/bash

echo -n "libkcrypto  [blob-keys]: "

. test-preset.inc
. kc-test.inc

if ! test_cbc; then
	echo Skipped
	exit 0
fi

fail=n
iv=000102030405060708090a0b0c0d0e0f

# An empty blob is a wrong argument; one the kernel does not load is a
# failure, with the kernel's errno: ENODEV without trusted keys, EINVAL
# for a blob no trust source takes
expect 2 'kc-check: status=2 errnum=22: empty key blob' \
	cipher enc "$cbc" blob: $iv
rc=0
kc-check cipher enc "$cbc" blob:00 $iv < /dev/null 2> $NAME.err || rc=$?
if [ $rc -ne 3 ] || ! grep -qx 'kc-check: status=3 errnum=[0-9]*: cannot load the trusted key blob: .*' \
	$NAME.err; then
	echo "kc-check cipher with blob:00: exit $rc, $(cat $NAME.err)"
	fail=y
fi

. test-end.inc
