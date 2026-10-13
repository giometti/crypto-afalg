#!/bin/bash

echo -n "craf        [keys]: "

. test-preset.inc
. craf-test.inc

fail=n
craf_plain > $NAME.in
craf_fixed_archive $NAME.craf || fail=y
head -c 16 /dev/urandom > $NAME-short.bin
short=$(keyctl padd user $NAME-short @s < $NAME-short.bin)

# An archive made by openssl unseals
craf unseal -enc-key $good < $NAME.craf > $NAME.out || fail=y
cmp $NAME.in $NAME.out || fail=y

# A wrong key gives a wrong padding: fixed, as the archive, every time
craf_expect 1 'bad decrypt (wrong padding)' $NAME.craf unseal -enc-key $bad

# A key that is not there could not be used
craf_expect 3 "cannot get ID for user key $NAME-none in keyring @s" \
	$NAME.craf unseal -enc-key @s,user,$NAME-none

# Keys given wrongly
craf_expect 2 'unknown keyring name "nokeyring"' $NAME.craf \
	unseal -enc-key nokeyring,user,x
craf_expect 2 'invalid key serial number' $NAME.craf unseal -enc-key 0
craf_expect 2 'unseal: -enc-key is required' $NAME.craf unseal
craf_expect 2 'seal: -enc-key is required' $NAME.in seal -cipher-driver $driver
craf_expect 2 'is 16 bytes, not 32' $NAME.in \
	seal -cipher-driver $driver -enc-key $short

# A description held twice is ambiguous
ring=$(keyctl newring $NAME-ring @s)
craf_add_key $NAME-good $CRAF_KEY_BAD $ring > /dev/null
craf_expect 2 "more than one user key $NAME-good in keyring @s" $NAME.craf \
	unseal -enc-key @s,user,$NAME-good

. test-end.inc
