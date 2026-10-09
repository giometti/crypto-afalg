#!/bin/bash

echo -n "output      [unwritable-stdout]: "

. test-preset.inc

key=06a9214036b8a15b512e03d534120006
iv=3dafba429d9eb430b422da802c9fac41

# usage: unwritable <input file> <crypto-afalg arguments...>
unwritable () {
	local in=$1 rc=0

	shift
	if [ -c /dev/full ] && [ -w /dev/full ] ; then
		crypto-afalg "$@" < $in > /dev/full 2> $NAME.err || rc=$?
	else
		# No /dev/full: a file size limit of 0 makes every write to a
		# file fail, so stderr leaves through a pipe, which it spares
		{ ( trap '' XFSZ ; ulimit -f 0 ; \
		    crypto-afalg "$@" < $in > $NAME.full ) 2>&1 | \
			cat > $NAME.err ; } || rc=$?
	fi
	[ $rc -eq 1 ] || fail=y
	grep -q 'cannot write output' $NAME.err || fail=y
}

fail=n
head -c $((16384 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
crypto-afalg encrypt aes-128-cbc -K $key -V $iv < $NAME.in > $NAME.enc

# An output that cannot be written is an error
unwritable $NAME.in encrypt aes-128-cbc -K $key -V $iv
unwritable $NAME.enc decrypt aes-128-cbc -K $key -V $iv
unwritable $NAME.in hash sha-256

# A writable one still works
crypto-afalg decrypt aes-128-cbc -K $key -V $iv < $NAME.enc > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y
sha256sum < $NAME.in | cut -d ' ' -f1 > $NAME.ref
crypto-afalg hash sha-256 < $NAME.in > $NAME.out || fail=y
diff -u $NAME.ref $NAME.out || fail=y

. test-end.inc
