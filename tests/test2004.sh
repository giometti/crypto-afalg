#!/bin/bash

echo -n "craf        [bad-body]: "

. test-preset.inc
. craf-test.inc

fail=n
craf_plain > $NAME.in
craf seal -cipher-driver $driver -enc-key $good \
	< $NAME.in > $NAME.good || fail=y
size=$(stat -c %s $NAME.good)
hdr_len=$((46 + ${#driver}))

# One bit off in the last byte of the next to last block is one bit off
# in the padding, which then is wrong whatever the IV
cp $NAME.good $NAME.craf
craf_patch $NAME.craf $((size - 17)) \
	"$(craf_xor_byte $NAME.good $((size - 17)) 1)"
craf_expect 1 'bad decrypt (wrong padding)' $NAME.craf unseal -enc-key $good

# Cut inside the header, or to a body that is not of whole blocks
for len in 0 11 $((hdr_len - 1)); do
	head -c $len $NAME.good > $NAME.craf
	craf_expect 1 'truncated header' $NAME.craf unseal -enc-key $good
done
for len in $hdr_len $((hdr_len + 15)) $((size - 1)); do
	head -c $len $NAME.good > $NAME.craf
	craf_expect 1 'bad decrypt (wrong final block length)' $NAME.craf \
		unseal -enc-key $good
done
cp $NAME.good $NAME.craf
printf 'x' >> $NAME.craf
craf_expect 1 'bad decrypt (wrong final block length)' $NAME.craf \
	unseal -enc-key $good

# Cut by whole blocks: the last byte left is one of the input, not padding
for len in $((size - 16)) $((size - 32)); do
	head -c $len $NAME.good > $NAME.craf
	craf_expect 1 'bad decrypt (wrong padding)' $NAME.craf \
		unseal -enc-key $good
done

. test-end.inc
