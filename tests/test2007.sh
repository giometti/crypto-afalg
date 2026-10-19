#!/bin/bash

echo -n "craf        [trusted]: "

. test-preset.inc
. craf-test.inc

# A trusted key, if the kernel has a trust source; CRAF_TEST_TRUSTED
# holds the options of "new" it needs (keyhandle=... on a TPM 2.0), and
# given, it says the key can be made: then not making it is a failure
rc=0
tkey=$(keyctl add trusted $NAME-t "new 32 $CRAF_TEST_TRUSTED" @s \
	2> $NAME.err) || rc=$?
if [ $rc -ne 0 ]; then
	if [ -n "$CRAF_TEST_TRUSTED" ]; then
		echo "keyctl add trusted: $(cat $NAME.err)"
		echo KO!
		exit 1
	fi
	craf_skip "$(cat $NAME.err)"
fi

fail=n
keyctl pipe $tkey > $NAME.blob || fail=y
blob=$(cat $NAME.blob)
d=${#driver}
hdr_len=$((49 + d + ${#blob} / 2))
head -c $((1 + RANDOM % 20000)) /dev/urandom > $NAME.in

# Sealed with the blob, unsealed with no key option, pipe to pipe
cat $NAME.in | craf seal -cipher-driver $driver -enc-blob $NAME.blob |
	cat > $NAME.craf || fail=y
cat $NAME.craf | craf unseal | cat > $NAME.out || fail=y
cmp $NAME.in $NAME.out || fail=y

# The header as the format lays it out, the blob as keyctl gave it
iv=$(od -An -tx1 -v -j$((31 + d)) -N16 $NAME.craf | tr -d ' \n')
craf_header $iv $driver $blob > $NAME.ref
head -c $hdr_len $NAME.craf | cmp - $NAME.ref || fail=y

# The body is encrypted with the key of the blob: under a header of
# source serial it opens with the trusted key as the kernel created it,
# not as craf loaded it
{
	craf_header $iv
	tail -c +$((hdr_len + 1)) $NAME.craf
} > $NAME.serial
craf unseal -enc-key $tkey < $NAME.serial > $NAME.out || fail=y
cmp $NAME.in $NAME.out || fail=y

# And what that key sealed opens from the blob alone
craf seal -cipher-driver $driver -enc-key $tkey \
	< $NAME.in > $NAME.serial || fail=y
iv=$(od -An -tx1 -v -j$((30 + d)) -N16 $NAME.serial | tr -d ' \n')
{
	craf_header $iv $driver $blob
	tail -c +$((47 + d)) $NAME.serial
} > $NAME.craf
craf unseal < $NAME.craf > $NAME.out || fail=y
cmp $NAME.in $NAME.out || fail=y

# The blob file as keyctl print writes it, with a final newline, or in
# capitals: the header holds the same bytes
for form in nl caps; do
	case $form in
	nl) echo $blob > $NAME.blob2 ;;
	caps) printf %s $blob | tr a-f A-F > $NAME.blob2 ;;
	esac
	craf seal -cipher-driver $driver -enc-blob $NAME.blob2 \
		< $NAME.in > $NAME.craf || fail=y
	head -c $hdr_len $NAME.craf | tail -c +$((50 + d)) |
		cmp - <(craf_bytes $blob) || fail=y
	craf unseal < $NAME.craf > $NAME.out || fail=y
	cmp $NAME.in $NAME.out || fail=y
done

. test-end.inc
