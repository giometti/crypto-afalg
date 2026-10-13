#!/bin/bash

echo -n "craf        [format-openssl]: "

. test-preset.inc
. craf-test.inc

fail=n
head -c $((1 + RANDOM % 20000)) /dev/urandom > $NAME.in
craf seal -cipher-driver $driver -enc-key $good \
	< $NAME.in > $NAME.craf || fail=y

# The header as the format lays it out; only the IV is random
hdr_len=$((46 + ${#driver}))
head -c $hdr_len $NAME.craf > $NAME.hdr
iv=$(tail -c 16 $NAME.hdr | od -An -tx1 -v | tr -d ' \n')
craf_header $iv > $NAME.ref
cmp $NAME.ref $NAME.hdr || fail=y

# The body is AES-256-CBC of the input with PKCS#7 padding
tail -c +$((hdr_len + 1)) $NAME.craf |
	openssl enc -d -aes-256-cbc -K $CRAF_KEY_GOOD -iv $iv \
		> $NAME.out || fail=y
cmp $NAME.in $NAME.out || fail=y

. test-end.inc
