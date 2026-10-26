#!/bin/bash

echo -n "libkcrypto  [driver-choice]: "

. test-preset.inc
. kc-test.inc

if ! test_cbc; then
	echo Skipped
	exit 0
fi

# What /proc/crypto lists decides, in a mount namespace of the test's own
# where it lists drivers made up to tell every rule of the choice apart:
# only the bind() reaches the kernel
fail=n
entry () {	# <driver> <type> <priority> <selftest> <internal>
	printf 'name         : cbc(aes)\ndriver       : %s\n' $1
	printf 'module       : kernel\npriority     : %s\nrefcnt       : 1\n' $3
	printf 'selftest     : %s\ninternal     : %s\ntype         : %s\n\n' \
		$4 $5 $2
}
{
	entry low skcipher 100 passed no
	entry untested skcipher 900 unknown no
	entry internal skcipher 800 passed yes
	entry hashed ahash 700 passed no
	entry high lskcipher 300 passed no
	entry equal skcipher 300 passed no
	entry old blkcipher 200 passed no
} > $NAME.crypto
if ! unshare -rm sh -c "mount --bind $PWD/$NAME.crypto /proc/crypto" \
	2> /dev/null; then
	echo "Skipped (no mount namespace)"
	exit 0
fi

# The highest priority among the tested, not internal drivers of a type
# the socket takes, the first among equals; and the kernels before 5.5
cat > $NAME.ns << EOS
mount --bind $PWD/$NAME.crypto /proc/crypto || exit 1
kc-check driver-for-algo skcipher 'cbc(aes)' > $NAME.choice || exit 2
kc-check driver skcipher old 'cbc(aes)' || exit 3
kc-check driver hash hashed 'cbc(aes)' || exit 4
rc=0
kc-check driver skcipher hashed 'cbc(aes)' 2> /dev/null || rc=\$?
[ \$rc -eq 1 ] || exit 5
exit 0
EOS
rc=0
unshare -rm sh $NAME.ns || rc=$?
if [ $rc -ne 0 ]; then
	echo "in the namespace: step $rc failed"
	fail=y
fi
[ "$(cat $NAME.choice)" = high ] || fail=y

. test-end.inc
