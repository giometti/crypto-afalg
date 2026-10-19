#!/bin/bash

echo -n "craf        [blob-usage]: "

. test-preset.inc
. craf-test.inc

fail=n
craf_plain > $NAME.in
craf_fixed_archive $NAME.serial || fail=y
d=${#driver}

# A well formed blob that no trust source loads
junk=00112233445566778899aabbccddeeff
printf %s $junk > $NAME.blob

# The fixed archive under a header of source trusted with the junk blob
{
	craf_header $CRAF_IV $driver $junk
	tail -c +$((47 + d)) $NAME.serial
} > $NAME.craf

craf -help > $NAME.help || fail=y
grep -q -- '-enc-key <key> | -enc-blob <file>' $NAME.help || fail=y

# One key option for seal; for unseal, -enc-key only where the archive
# needs it
craf_expect 2 'seal: give -enc-key or -enc-blob, not both' $NAME.in \
	seal -cipher-driver $driver -enc-key $good -enc-blob $NAME.blob
craf_expect 2 'seal: -enc-key or -enc-blob is required' $NAME.in \
	seal -cipher-driver $driver
craf_expect 2 'unseal: -enc-blob is for seal only' $NAME.craf \
	unseal -enc-blob $NAME.blob
craf_expect 2 'unseal: the archive carries its key, -enc-key is not for it' \
	$NAME.craf unseal -enc-key $good
craf_expect 2 'unseal: the archive needs -enc-key' $NAME.serial unseal

# The output cannot be the -enc-blob file, which it would empty
cp $NAME.blob $NAME.same
craf_expect 2 'the output and the -enc-blob file are the same file' $NAME.in \
	seal -cipher-driver $driver -enc-blob $NAME.same -out $NAME.same
cmp $NAME.blob $NAME.same || fail=y

# A blob file is hex, a final newline at most
bad_blob () {	# <content, as printf takes it> [<reason>]
	printf "$1" > $NAME.bad
	craf_expect 2 "-enc-blob: $NAME.bad ${2:-is not a key blob in hex}" \
		$NAME.in seal -cipher-driver $driver -enc-blob $NAME.bad
}
bad_blob '' 'is empty'
bad_blob '\n' 'is empty'
bad_blob '001'
bad_blob '00zz'
bad_blob ' 0011'
bad_blob '0011\n\n'
head -c 65536 /dev/zero | od -An -tx1 -v | tr -d ' \n' > $NAME.long
craf_expect 2 'holds a blob longer than 65535 bytes' $NAME.in \
	seal -cipher-driver $driver -enc-blob $NAME.long
craf_expect 3 "-enc-blob: cannot open $NAME.none" $NAME.in \
	seal -cipher-driver $driver -enc-blob $NAME.none
mkdir -p $NAME.dir
craf_expect 3 "-enc-blob: cannot read $NAME.dir" $NAME.in \
	seal -cipher-driver $driver -enc-blob $NAME.dir

# A blob the kernel does not load could not be used; seal writes nothing
head -c 65535 /dev/zero | od -An -tx1 -v | tr -d ' \n' > $NAME.long
craf_expect 3 "cannot load the trusted key blob in $NAME.long" $NAME.in \
	seal -cipher-driver $driver -enc-blob $NAME.long
craf_expect 3 "cannot load the trusted key blob in $NAME.blob" $NAME.in \
	seal -cipher-driver $driver -enc-blob $NAME.blob
rc=0
craf seal -cipher-driver $driver -enc-blob $NAME.blob \
	-in $NAME.in -out $NAME.out 2> /dev/null || rc=$?
[ $rc -eq 3 ] || fail=y
[ -s $NAME.out ] && fail=y
craf_expect 3 'cannot load the trusted key blob the archive carries' \
	$NAME.craf unseal

# The blob field: not empty, within the header, and ending it
patched () {	# <offset> <bytes> <reason>
	cp $NAME.craf $NAME.p
	craf_patch $NAME.p $1 "$2"
	craf_expect 1 "$3" $NAME.p unseal
}
patched $((47 + d)) '\000\000' 'header field "blob" is empty'
patched $((47 + d)) '\021\000' 'header field "blob" runs past the header'
patched $((47 + d)) '\017\000' "inconsistent hdr_len $((65 + d))"

. test-end.inc
