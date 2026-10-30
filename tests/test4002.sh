#!/bin/bash

echo -n "kcdm        [loop]: "

. test-preset.inc
. kcdm-test.inc

# This test makes device-mapper devices: it runs only when asked for,
# with KCDM_TEST_LOOP=1, as root, where there are loop devices
if [ "$KCDM_TEST_LOOP" != 1 ]; then
	echo "Skipped (KCDM_TEST_LOOP=1 not set)"
	exit 0
fi
[ "$(id -u)" -eq 0 ] || {
	echo "Skipped (not root)"
	exit 0
}
for tool in losetup openssl keyctl; do
	type $tool > /dev/null 2>&1 || {
		echo "Skipped (no $tool)"
		exit 0
	}
done
[ -c /dev/mapper/control ] || {
	echo "Skipped (no /dev/mapper/control)"
	exit 0
}
if ! keyctl new_session > /dev/null 2> $NAME.err; then
	echo "Skipped (keyctl new_session: $(cat $NAME.err))"
	exit 0
fi

name=kcdm-test-$$
other=kcdm-test-$$-other
for n in $name $other; do
	kcdm_unused $n || {
		echo "$n: in use"
		echo KO!
		exit 1
	}
done
head -c 4194304 /dev/zero > $NAME.img
head -c 1048576 /dev/zero > $NAME.img2
loop= loop2=
trap 'kcdm close $name > /dev/null 2>&1 || :
	kcdm close $other > /dev/null 2>&1 || :
	[ -z "$loop" ] || losetup -d $loop || :
	[ -z "$loop2" ] || losetup -d $loop2 || :
	rm -f $NAME.img $NAME.img2' EXIT
if ! loop=$(losetup -f --show $NAME.img 2> $NAME.err) ||
	! loop2=$(losetup -f --show $NAME.img2 2>> $NAME.err); then
	echo "losetup: $(cat $NAME.err)"
	echo KO!
	exit 1
fi

fail=n
cipher='capi:cbc(aes)-plain'
hex=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
keyctl padd user $NAME @s < <(printf "$(sed 's/../\\x&/g' <<< $hex)") \
	> /dev/null
key=@s,user,$NAME

# Opened, written through the device, closed: the sectors of the loop
# device are those openssl, the oracle, encrypts with the plain IV of
# dm-crypt, the sector number in 32 bits, little endian. Nothing is
# written unless the node is the device's, so that no file takes its place
kcdm_expect 0 - open $loop $name -cipher $cipher -key $key -key-size 32
if [ ! -b /dev/mapper/$name ]; then
	echo "/dev/mapper/$name: not a block device"
	echo KO!
	exit 1
fi
head -c 65536 /dev/urandom > $NAME.in
dd if=$NAME.in of=/dev/mapper/$name bs=4096 conv=fsync,nocreat 2> /dev/null

# The name in use, on another device; the device mapped already, under
# another name
kcdm_expect 3 "kcdm: open: cannot create $name: Device or resource busy (the name is in use; closing it frees one left over)" \
	open $loop2 $name -cipher $cipher -key $key -key-size 32
kcdm_expect 3 "kcdm: open: cannot open $loop: Device or resource busy (mounted, or mapped already?)" \
	open $loop $other -cipher $cipher -key $key -key-size 32
kcdm_expect 0 - close $name
if ! kcdm_unused $name; then
	echo "$name: still there after close"
	fail=y
fi
for s in 0 1 127; do
	iv=$(printf '%08x' $s | sed 's/\(..\)\(..\)\(..\)\(..\)/\4\3\2\1/')
	dd if=$NAME.in bs=512 skip=$s count=1 2> /dev/null > $NAME.exp
	if ! dd if=$NAME.img bs=512 skip=$s count=1 2> /dev/null |
		openssl enc -d -aes-256-cbc -nopad -K $hex \
			-iv ${iv}000000000000000000000000 > $NAME.dec ||
		! cmp -s $NAME.dec $NAME.exp; then
		echo "sector $s: not what openssl decrypts"
		fail=y
	fi
done

# The same data back, with a parameter of dm-crypt that changes nothing
kcdm_expect 0 - open $loop $name -cipher $cipher -key $key -key-size 32 \
	-opt sector_size:512
if ! dd if=/dev/mapper/$name bs=4096 count=16 2> /dev/null |
	cmp -s - $NAME.in; then
	echo "-opt sector_size:512: not the data written"
	fail=y
fi

# In use, it stays, after the tries of a while
exec 3< /dev/mapper/$name
kcdm_expect 3 "kcdm: close: cannot remove $name: Device or resource busy (it is in use, mounted or open)" \
	close $name
exec 3<&-
kcdm_expect 0 - close $name

# What the kernel refuses leaves the name free; the kernel says which
# errno
kcdm_expect 3 "kcdm: open: the kernel does not take the table of $name: Invalid argument (its log may say why)" \
	open $loop $name -cipher $cipher -key $key -key-size 16
kcdm_expect 3 "kcdm: open: the kernel does not take the table of $name: Invalid argument (its log may say why)" \
	open $loop $name -cipher $cipher -key $key -key-size 32 -opt kcdm_none
kcdm_expect 3 "kcdm: open: the kernel does not take the table of $name: No such file or directory (no cipher capi:kcdm(none)-plain in the kernel, or its driver not registered yet?)" \
	open $loop $name -cipher 'capi:kcdm(none)-plain' -key $key -key-size 32
if ! kcdm_unused $name; then
	echo "$name: left after a refusal"
	fail=y
fi

. test-end.inc
