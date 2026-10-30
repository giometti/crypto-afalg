#!/bin/bash

echo -n "kcdm        [usage-key]: "

. test-preset.inc
. kcdm-test.inc

if ! keyctl new_session > /dev/null 2> $NAME.err; then
	echo "Skipped (keyctl new_session: $(cat $NAME.err))"
	exit 0
fi

# No open here gets as far as /dev/mapper/control: each one has a wrong
# usage, a key dm-crypt cannot take or a device that is no block device,
# so that a run as root never makes a device-mapper device. The cases of
# a real device are on a loop device, test4002.
fail=n
cipher='capi:cbc(aes)-plain'
keyctl add user $NAME-k 0123456789abcdef0123456789abcdef @s > /dev/null
key=@s,user,$NAME-k
open="open /dev/null $NAME"

# Help and version
rc=0
kcdm < /dev/null > $NAME.out 2> $NAME.err || rc=$?
if [ $rc -ne 2 ] || [ -s $NAME.out ] ||
	[ "$(head -n 1 $NAME.err)" != 'usage: kcdm -help | -version | <command> [ <arguments> ]' ]; then
	echo "kcdm: exit $rc, $(cat $NAME.out $NAME.err)"
	fail=y
fi
for args in -help help 'open -help' 'close -help' 'open --help'; do
	kcdm_expect 0 - $args
	if [ "$(head -n 1 $NAME.out)" != 'usage: kcdm -help | -version | <command> [ <arguments> ]' ]; then
		echo "kcdm $args: $(cat $NAME.out)"
		fail=y
	fi
done
kcdm_expect 0 - -version
read -r name version < $NAME.out
if [ "$name" != kcdm ] || [ "$version" != "$($SRCDIR/tools/git-version.sh)" ]; then
	echo "kcdm -version: $(cat $NAME.out)"
	fail=y
fi

# Wrong usage of the command line
kcdm_expect 2 'kcdm: unknown command "list", see -help' list
for args in open 'open /dev/null' "open -cipher $cipher" \
	"open /dev/null -cipher $cipher"; do
	kcdm_expect 2 'kcdm: open: <device> and <name> come first, then the options; see -help' \
		$args
done
kcdm_expect 2 'kcdm: open: -cipher is required' $open -key $key -key-size 32
kcdm_expect 2 'kcdm: open: -key is required' $open -cipher $cipher -key-size 32
kcdm_expect 2 'kcdm: open: -key-size is required' $open -cipher $cipher -key $key
kcdm_expect 2 'kcdm: open: -cipher given twice' \
	$open -cipher $cipher -key $key -key-size 32 -cipher $cipher
kcdm_expect 2 'kcdm: open: -key given twice' \
	$open -cipher $cipher -key $key -key-size 32 -key $key
kcdm_expect 2 'kcdm: open: -key-size given twice' \
	$open -cipher $cipher -key $key -key-size 32 -key-size 32
kcdm_expect 2 'kcdm: open: unknown option or missing value "-type", see -help' \
	$open -type crypt -cipher $cipher -key $key -key-size 32
kcdm_expect 2 'kcdm: open: unknown option or missing value "-key-size", see -help' \
	$open -cipher $cipher -key $key -key-size
kcdm_expect 2 'kcdm: open: unexpected argument "extra"' \
	$open -cipher $cipher -key $key -key-size 32 extra
for size in 0 -1 +32 32x ' 32' 0x20 '' 2147483648; do
	kcdm_expect 2 "kcdm: -key-size: \"$size\" is not a number of bytes from 1 to 2147483647" \
		$open -cipher $cipher -key $key -key-size "$size"
done
kcdm_expect 2 'kcdm: close: give the name only, see -help' close
kcdm_expect 2 'kcdm: close: give the name only, see -help' close a b

# What dm-crypt cannot take in its table, a wrong usage even with a key
# that is not there
none=@s,user,$NAME-none
for opt in 'sector_size: 512' '' $'sector_size:512\xa01' 'a\b'; do
	kcdm_expect 2 'kcdm: open: a parameter of dm-crypt is one word, with no white space nor backslash' \
		$open -cipher $cipher -key $none -key-size 32 -opt "$opt"
done
for c in 'capi:cbc(aes) -plain' $'capi:cbc(aes)\xa0-plain' 'capi:cbc(aes)\'; do
	kcdm_expect 2 'kcdm: open: the cipher is one word, with no white space nor backslash' \
		open /dev/null $NAME -cipher "$c" -key $none -key-size 32
done
kcdm_expect 2 'kcdm: open: "a/b" cannot name a device of /dev/mapper' \
	open /dev/null a/b -cipher $cipher -key $none -key-size 32
kcdm_expect 2 'kcdm: open: the name of a device has no white space nor control characters' \
	open /dev/null 'a b' -cipher $cipher -key $none -key-size 32
kcdm_expect 2 'kcdm: close: "a/b" cannot name a device of /dev/mapper' close a/b

# -key as craf -enc-key takes it: a malformed or ambiguous spec is a wrong
# usage, a key that is not there could not be used
kcdm_expect 2 'kcdm: -key: unknown keyring name "@x"' \
	$open -cipher $cipher -key @x,user,$NAME-k -key-size 32
kcdm_expect 2 'kcdm: -key: invalid key serial number "12ab"' \
	$open -cipher $cipher -key 12ab -key-size 32
kcdm_expect 3 "kcdm: -key: cannot get ID for user key $NAME-none in keyring @s: Required key not available" \
	$open -cipher $cipher -key $none -key-size 32
kr=$(keyctl newring $NAME-ring @s)
a=$(keyctl add user $NAME-dup aaaa @s)
b=$(keyctl add user $NAME-dup bbbb $kr)
kcdm_expect 2 "kcdm: -key: more than one user key $NAME-dup in keyring @s" \
	$open -cipher $cipher -key @s,user,$NAME-dup -key-size 32

# A key dm-crypt cannot take, by its spec or by its serial: of another
# type, or not the one dm-crypt finds first by its type and description
for spec in @s,keyring,$NAME-ring $kr; do
	kcdm_expect 3 "kcdm: open: the key $kr is of type keyring: dm-crypt takes logon, user, encrypted and trusted keys" \
		$open -cipher $cipher -key $spec -key-size 32
done
kcdm_expect 3 "kcdm: open: the user key $NAME-dup that dm-crypt would take is $a, not $b" \
	$open -cipher $cipher -key $b -key-size 32

# A device that is not there, or is not a block device
kcdm_expect 3 "kcdm: open: cannot open $NAME.none: No such file or directory" \
	open $NAME.none $NAME -cipher $cipher -key $key -key-size 32
kcdm_expect 3 'kcdm: open: /dev/null: Block device required' \
	$open -cipher $cipher -key $key -key-size 32 -opt sector_size:512

# close of a name no device has: root asks the kernel only once the name
# is seen unused, anybody else cannot ask
absent=kcdm-test-$$-absent
if [ "$(id -u)" -ne 0 ]; then
	rc=0
	kcdm close $absent > /dev/null 2> $NAME.err || rc=$?
	if [ $rc -ne 3 ] ||
		! grep -qx 'kcdm: close: cannot open /dev/mapper/control: .*' $NAME.err; then
		echo "kcdm close $absent: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
elif ! kcdm_unused $absent; then
	echo "$absent: in use, not asked"
	fail=y
else
	kcdm_expect 3 "kcdm: close: $absent: no such device" close $absent
fi

. test-end.inc
