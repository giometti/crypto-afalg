#!/bin/bash

echo -n "libkcrypto  [dm]: "

. test-preset.inc
. kc-test.inc

if ! keyctl new_session > /dev/null 2> $NAME.err; then
	echo "Skipped (keyctl new_session: $(cat $NAME.err))"
	exit 0
fi

# No case here gets as far as /dev/mapper/control on kc_dm_open(): each
# one has a wrong argument, a key dm-crypt cannot take or a device that is
# no block device, so that a run as root never makes a device-mapper
# device. The cases of a real device are on a loop device, test4002.
fail=n
cipher='capi:cbc(aes)-plain'
k=$(keyctl add user $NAME-k 0123456789abcdef0123456789abcdef @s)
key=spec:@s,user,$NAME-k
usage='kc-check: status=2 errnum=22:'
nbsp=$'\xa0'

# Wrong arguments, KC_USAGE
expect 2 "$usage no flag is defined yet" \
	dm-open $NAME /dev/null "$cipher" $key 32 1
long=$(printf '%0128d' 0)
for name in - '' $long; do
	expect 2 "$usage the name of a device is 1 to 127 characters long" \
		dm-open "$name" /dev/null "$cipher" $key 32 0
done
for name in 'a b' $'a\001b' "a${nbsp}b"; do
	expect 2 "$usage the name of a device has no white space nor control characters" \
		dm-open "$name" /dev/null "$cipher" $key 32 0
done
for name in a/b . .. control; do
	expect 2 "$usage \"$name\" cannot name a device of /dev/mapper" \
		dm-open "$name" /dev/null "$cipher" $key 32 0
done

# A word of the table is one for the kernel too: its white space takes
# 0xa0, and a backslash quotes the character after it
for c in '' 'capi:cbc(aes) -plain' "capi:cbc(aes)${nbsp}-plain" \
	'capi:cbc(aes)-plain\'; do
	expect 2 "$usage the cipher is one word, with no white space nor backslash" \
		dm-open $NAME /dev/null "$c" $key 32 0
done
for size in 0 2147483648; do
	expect 2 "$usage the key size is 1 to 2147483647 bytes" \
		dm-open $NAME /dev/null "$cipher" $key $size 0
done
for opt in '' 'sector_size: 512' "sector_size:512${nbsp}1" 'a\b'; do
	expect 2 "$usage a parameter of dm-crypt is one word, with no white space nor backslash" \
		dm-open $NAME /dev/null "$cipher" $key 32 0 allow_discards "$opt"
done
expect 2 "$usage no device" dm-open $NAME - "$cipher" $key 32 0
for raw in - hex:00112233; do
	expect 2 "$usage not a keyring key" \
		dm-open $NAME /dev/null "$cipher" $raw 32 0
done

# The longest name and the largest key size are taken: what stops them is
# the device
expect 3 'kc-check: status=3 errnum=15: /dev/null: Block device required' \
	dm-open ${long:1} /dev/null "$cipher" $key 2147483647 0

# A key dm-crypt cannot take: of another type, with white space (0xa0
# too) or a backslash in its description, one dm-crypt does not reach, or
# one it would not find first by its type and description, which are
# what the table names
kr=$(keyctl newring $NAME-ring @s)
expect 3 "kc-check: status=3 errnum=22: the key $kr is of type keyring: dm-crypt takes logon, user, encrypted and trusted keys" \
	dm-open $NAME /dev/null "$cipher" spec:$kr 32 0
for desc in "$NAME s" "$NAME${nbsp}s" "$NAME\\s"; do
	s=$(keyctl add user "$desc" 0123 @s)
	expect 3 "kc-check: status=3 errnum=22: the key $s has white space or a backslash in its description, which dm-crypt does not take" \
		dm-open $NAME /dev/null "$cipher" spec:$s 32 0
done
n=$(keyctl add user $NAME-n 0123 @s)
keyctl setperm $n 0x37010000
expect 3 "kc-check: status=3 errnum=13: the user key $NAME-n cannot be reached from the keyrings of this process: Permission denied" \
	dm-open $NAME /dev/null "$cipher" spec:$n 32 0
a=$(keyctl add user $NAME-dup aaaa @s)
b=$(keyctl add user $NAME-dup bbbb $kr)
expect 3 "kc-check: status=3 errnum=76: the user key $NAME-dup that dm-crypt would take is $a, not $b" \
	dm-open $NAME /dev/null "$cipher" spec:$b 32 0
expect 3 'kc-check: status=3 errnum=15: /dev/null: Block device required' \
	dm-open $NAME /dev/null "$cipher" spec:$a 32 0

# A device that is not there, or is not a block device; a FIFO is not
# waited on
expect 3 "kc-check: status=3 errnum=2: cannot open $NAME.none: No such file or directory" \
	dm-open $NAME $NAME.none "$cipher" $key 32 0
: > $NAME.file
expect 3 "kc-check: status=3 errnum=15: $NAME.file: Block device required" \
	dm-open $NAME $NAME.file "$cipher" $key 32 0
mkfifo $NAME.fifo
rc=0
timeout 10 kc-check dm-open $NAME $NAME.fifo "$cipher" $key 32 0 \
	< /dev/null 2> $NAME.err || rc=$?
if [ $rc -ne 3 ] ||
	[ "$(cat $NAME.err)" != "kc-check: status=3 errnum=15: $NAME.fifo: Block device required" ]; then
	echo "dm-open of a FIFO: exit $rc (124: it waited), $(cat $NAME.err)"
	fail=y
fi

# kc_dm_close(): a wrong name; a name no device has, which root asks the
# kernel about only once it is seen unused, and anybody else cannot ask
expect 2 "$usage the name of a device is 1 to 127 characters long" \
	dm-close -
expect 2 "$usage \"a/b\" cannot name a device of /dev/mapper" dm-close a/b
absent=kcdm-test-$$-absent
if [ "$(id -u)" -ne 0 ]; then
	rc=0
	kc-check dm-close $absent > /dev/null 2> $NAME.err || rc=$?
	if [ $rc -ne 3 ] ||
		! grep -q '^kc-check: status=3 errnum=[0-9]*: cannot open /dev/mapper/control: ' $NAME.err; then
		echo "dm-close $absent: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
elif [ -e /dev/mapper/$absent ] ||
	grep -qsxF -e $absent /sys/block/dm-*/dm/name; then
	echo "$absent: in use, not asked"
	fail=y
else
	expect 3 "kc-check: status=3 errnum=6: $absent: no such device" \
		dm-close $absent
fi

. test-end.inc
