#!/bin/bash

echo -n "kernel algo [bind]: "

. test-preset.inc

fail=n
key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
iv=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
seq 1 500 > $NAME.in

# An algorithm of the table the kernel does not have is not available,
# asked to the kernel: the CAAM one, where /proc/crypto does not list it
if grep -q -E '^name *: tk\(cbc\(aes\)\)$' /proc/crypto; then
	echo -n "(tk(cbc(aes)) listed) "
else
	rc=0
	crypto-afalg encrypt check-kalgo 'tk(cbc(aes))' || rc=$?
	[ $rc -eq 1 ] || fail=y
	head -c 52 /dev/zero | od -An -tx1 -v | tr -d ' \n' > $NAME.k52
	rc=0
	crypto-afalg encrypt 'caam(aes-256-cbc)' -K $(cat $NAME.k52) -V $iv \
		< $NAME.in > /dev/null 2> $NAME.err || rc=$?
	if [ $rc -ne 1 ] || ! grep -qF \
		'algo "tk(cbc(aes))" is not available' $NAME.err; then
		echo "caam(aes-256-cbc): exit $rc, $(cat $NAME.err)"
		fail=y
	fi
fi

# A template the kernel builds on its first use, such as hmac(sha256), is
# listed in /proc/crypto only after that use. In a mount namespace of the
# test's own, a /proc/crypto that lists none of the algorithms used here
# stands for a kernel just booted: crypto-afalg must ask the kernel.
echo > $NAME.probe
if ! unshare -rm sh -c "mount --bind $PWD/$NAME.probe /proc/crypto" \
	2> /dev/null; then
	echo -n "(no mount namespace) "
	. test-end.inc
fi

# A kernel without the algorithms has nothing to show here
if ! check-kalgo hash 'hmac(sha256)' ||
	! check-kalgo encrypt 'cbc(aes)'; then
	echo -n "(no hmac(sha256) or cbc(aes)) "
	. test-end.inc
fi

openssl dgst -sha256 -mac HMAC -macopt hexkey:$key < $NAME.in |
	sed 's/^.*= //' > $NAME.hmac.ref
openssl enc -aes-256-cbc -K $key -iv $iv < $NAME.in > $NAME.enc.ref
awk -v RS= -v ORS='\n\n' \
	'!/(^|\n)name *: (hmac\(sha256\)|sha256|cbc\(aes\))(\n|$)/' \
	/proc/crypto > $NAME.crypto

# Exit statuses name the step that failed; the passphrase derives its key
# with PBKDF2 over hmac(sha256)
cat > $NAME.ns << EOF
mount --bind $PWD/$NAME.crypto /proc/crypto || exit 2
if grep -q -E '^name *: (hmac\(sha256\)|sha256|cbc\(aes\))$' /proc/crypto
then
	exit 3
fi
crypto-afalg hash hmac-sha-256 -K $key < $NAME.in > $NAME.hmac.out || exit 4
crypto-afalg encrypt aes-256-cbc -K $key -V $iv \
	< $NAME.in > $NAME.enc.out || exit 5
crypto-afalg encrypt aes-256-cbc -P secret < $NAME.in > $NAME.pass.out ||
	exit 6
crypto-afalg hash check-kalgo 'hmac(sha256)' || exit 7
crypto-afalg encrypt check-kalgo 'cbc(aes)' || exit 8
crypto-afalg hash > $NAME.hlist 2>&1 || exit 9
crypto-afalg encrypt > $NAME.clist 2>&1 || exit 10
exit 0
EOF
rc=0
unshare -rm sh $NAME.ns || rc=$?
if [ $rc -ne 0 ]; then
	echo "in the namespace: step $rc failed"
	fail=y
fi
cmp $NAME.hmac.ref $NAME.hmac.out || fail=y
cmp $NAME.enc.ref $NAME.enc.out || fail=y
openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:secret < $NAME.pass.out |
	cmp - $NAME.in || fail=y
grep -q '^crypto-afalg: - hmac-sha-256 ' $NAME.hlist || fail=y
grep -q '^crypto-afalg: - aes-256-cbc ' $NAME.clist || fail=y

. test-end.inc
