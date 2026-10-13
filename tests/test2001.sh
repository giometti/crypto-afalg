#!/bin/bash

echo -n "craf        [seal-unseal]: "

. test-preset.inc
. craf-test.inc

fail=n
hdr_len=$((46 + ${#driver}))
for size in 0 1 15 16 17 8191 8192 8193 $((100000 + RANDOM)); do
	head -c $size /dev/urandom > $NAME.in
	# From a pipe to a pipe, both ways
	cat $NAME.in |
		craf seal -cipher-driver $driver -enc-key $good |
		cat > $NAME.craf || fail=y
	cat $NAME.craf | craf unseal -enc-key $good |
		cat > $NAME.out || fail=y
	cmp $NAME.in $NAME.out || fail=y
	# The header, then the input padded to whole blocks
	[ $(stat -c %s $NAME.craf) -eq \
		$((hdr_len + (size / 16 + 1) * 16)) ] || fail=y
done

# Files, and a key by description
craf seal -in $NAME.in -out $NAME.craf -cipher-driver $driver \
	-enc-key @s,user,$NAME-good || fail=y
craf unseal -in $NAME.craf -out $NAME.out -enc-key $good || fail=y
cmp $NAME.in $NAME.out || fail=y

. test-end.inc
