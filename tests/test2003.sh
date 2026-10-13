#!/bin/bash

echo -n "craf        [bad-header]: "

. test-preset.inc
. craf-test.inc

fail=n
head -c 1000 /dev/urandom > $NAME.in
craf seal -cipher-driver $driver -enc-key $good \
	< $NAME.in > $NAME.good || fail=y
d=${#driver}

# Unseal a copy with <bytes> at <offset>: <status> and <reason>
patched () {	# <status> <offset> <bytes> <reason> [<key>]
	cp $NAME.good $NAME.craf
	craf_patch $NAME.craf $2 "$3"
	craf_expect $1 "$4" $NAME.craf unseal -enc-key ${5:-$good}
}

patched 1 0 'X' 'not a craf archive'
patched 1 8 '\000' 'unsupported version 0'
patched 1 10 '\013\000' 'inconsistent hdr_len 11'
patched 1 10 "\\$(printf %03o $((46 + d + 1)))" \
	"inconsistent hdr_len $((46 + d + 1))"
patched 1 10 '\377\377' 'truncated header'
patched 1 12 '\000' 'header field "cipher_driver" is empty'
patched 1 12 '\377' 'header field "cipher_driver" runs past the header'
patched 1 13 ' ' 'header field "cipher_driver" is not printable ASCII'
patched 1 $((13 + d)) '\000' 'header field "cipher_algo" is empty'
patched 1 $((20 + d)) 'd' 'unsupported cipher_algo "cbc(aed)"'
patched 1 $((22 + d)) '\020' 'unsupported key_len 16'
patched 3 $((24 + d)) 'S' 'unknown key_source "Serial": a newer craf may read it'

# A newer version may be a good archive, which this craf could not read
patched 3 8 '\002' 'version 2 needs a newer craf'

# The whole header, its driver included, is checked before the keyring
patched 1 8 '\000' 'unsupported version 0' @s,user,$NAME-none
patched 3 13 'Z' 'is not listed in /proc/crypto' @s,user,$NAME-none

# The driver of the header must already be listed as one of cbc(aes):
# otherwise it could not be used, unless with -any-driver
patched 3 13 'Z' 'is not listed in /proc/crypto'
craf unseal -any-driver -enc-key $good < $NAME.craf > $NAME.out || fail=y
cmp $NAME.in $NAME.out || fail=y

# Listed in /proc/crypto as a driver
listed () {	# <driver>
	CRAF_DRV=$1 awk -F ' *: ' '
		$1 == "driver" && $2 == ENVIRON["CRAF_DRV"] { found = 1 }
		END { exit !found }' /proc/crypto
}

# A driver the kernel would build from a template, named by a header,
# is not built: craf does not bind what is not listed
wrap='cbc(aes-generic)'
while listed "$wrap" && [ ${#wrap} -lt 200 ]; do
	wrap="cryptd($wrap)"
done
craf_fixed_archive $NAME.craf "$wrap" || fail=y
craf_expect 3 'is not listed in /proc/crypto' $NAME.craf unseal -enc-key $good
if listed "$wrap"; then
	echo "$wrap was built"
	fail=y
fi

# A header that names an algorithm names no driver the kernel lists
craf_fixed_archive $NAME.craf 'cbc(aes)' || fail=y
craf_expect 3 'is not listed in /proc/crypto' $NAME.craf unseal -enc-key $good

# A header that names a listed driver of another algorithm is false
ecb=$(craf_listed_driver 'ecb(aes)')
if [ -n "$ecb" ]; then
	craf_fixed_archive $NAME.craf $ecb || fail=y
	craf_expect 1 "is a driver of ecb(aes), not cbc(aes)" $NAME.craf \
		unseal -enc-key $good
	craf_plain | cmp - <(craf unseal -any-driver -enc-key $good \
		< $NAME.craf) || fail=y
else
	echo -n "(no ecb(aes) listed) "
fi

. test-end.inc
