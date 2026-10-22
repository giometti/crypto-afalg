#!/bin/bash

echo -n "driver      [force-driver]: "

. test-preset.inc

if ! test_cbc || ! check-kalgo hash sha256; then
	echo Skipped
	exit 0
fi

# usage: refused <driver> <type(algo)> <crypto-afalg args...>
refused () {
	local drv=$1 what=$2 rc=0

	shift 2
	crypto-afalg --force-driver "$drv" "$@" < $NAME.in \
		> /dev/null 2> $NAME.err || rc=$?
	if [ $rc -ne 1 ] || ! grep -qxF -e \
		"crypto-afalg: driver \"$drv\" is not available or not valid $what algo" \
		$NAME.err; then
		echo "--force-driver $drv $*: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
}

fail=n
key=06a9214036b8a15b512e03d534120006
iv=3dafba429d9eb430b422da802c9fac41
seq 1 1000 > $NAME.in

# The check-kalgo above made the kernel list the drivers it built
# CRAF_TEST_DRIVER: a usable one, where the kernel's own is not (README)
cbc=${CRAF_TEST_DRIVER:-$(driver_of 'cbc(aes)' skcipher lskcipher)}
sha=$(driver_of sha256 ahash shash)
if [ -z "$cbc" ] || [ -z "$sha" ]; then
	echo "no driver of cbc(aes) or sha256 in /proc/crypto"
	fail=y
fi

# A driver of the algorithm is used
openssl enc -aes-128-cbc -K $key -iv $iv < $NAME.in > $NAME.ref
crypto-afalg --force-driver "$cbc" encrypt aes-128-cbc -K $key -V $iv \
	< $NAME.in > $NAME.out || fail=y
cmp $NAME.ref $NAME.out || fail=y
sha256sum < $NAME.in | cut -d ' ' -f1 > $NAME.ref
crypto-afalg --force-driver "$sha" hash sha-256 < $NAME.in > $NAME.out ||
	fail=y
cmp $NAME.ref $NAME.out || fail=y

# One of another algorithm, or of no algorithm, is refused
refused "$sha" 'skcipher(cbc(aes))' encrypt aes-128-cbc -K $key -V $iv
refused "$cbc" 'hash(sha256)' hash sha-256
refused nosuch-driver 'skcipher(cbc(aes))' decrypt aes-128-cbc -K $key -V $iv

. test-end.inc
