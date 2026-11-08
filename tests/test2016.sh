#!/bin/bash

echo -n "craf        [info]: "

. test-preset.inc
. craf-format.inc

# info reads the header only: the archives are built here, with no key,
# openssl or driver
fail=n
iv=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
drv=cbc-aes-ce
head -c 64 /dev/zero > $NAME.data

# craf info <arguments> on <input>: exit <status> and exactly <expected>
# on stdout
info_is () {	# <status> <expected> <input> <arguments>...
	local exp=$1 out=$2 input=$3 rc=0
	shift 3
	craf info "$@" < $input > $NAME.out 2> $NAME.err || rc=$?
	if [ $rc -ne $exp ] || [ "$(cat $NAME.out)" != "$out" ]; then
		echo "craf info $*: exit $rc, $(cat $NAME.out) $(cat $NAME.err)"
		fail=y
	fi
}

craf -help > $NAME.help || fail=y
grep -q -- '  info \[ -in <file> \]' $NAME.help || fail=y

# Every field of the header but magic, the IV in hex; no key is needed
{
	craf_header $iv $drv
	cat $NAME.data
} > $NAME.serial
fields="version: 1
hdr_len: 56
cipher_driver: $drv
cipher_algo: cbc(aes)
key_len: 32
key_source: serial
iv: $iv"
info_is 0 "$fields" $NAME.serial
info_is 0 "$fields" /dev/null -in $NAME.serial

# Nothing past the header is read: no data at all, the same
craf_header $iv $drv > $NAME.bare
info_is 0 "$fields" $NAME.bare

# A trusted archive: the length of its blob, never the blob
blob=00112233445566778899aabbccddeeff
{
	craf_header $iv $drv $blob
	cat $NAME.data
} > $NAME.trusted
info_is 0 "version: 1
hdr_len: 75
cipher_driver: $drv
cipher_algo: cbc(aes)
key_len: 32
key_source: trusted
iv: $iv
blob_len: 16" $NAME.trusted

# What the header says, not that it is true: a driver nobody has
{
	craf_header $iv keycrypt@optee
	cat $NAME.data
} > $NAME.other
info_is 0 "version: 1
hdr_len: 60
cipher_driver: keycrypt@optee
cipher_algo: cbc(aes)
key_len: 32
key_source: serial
iv: $iv" $NAME.other

# Refused as unseal refuses it, with nothing on stdout
craf_plain > $NAME.plain
info_is 1 "" $NAME.plain
craf_expect 1 'not a craf archive' $NAME.plain info
head -c 30 $NAME.serial > $NAME.cut
craf_expect 1 'truncated header' $NAME.cut info
cp $NAME.serial $NAME.p
craf_patch $NAME.p 12 '\000'
craf_expect 1 'header field "cipher_driver" is empty' $NAME.p info

# Could not read it: a newer version, an unknown key source, no file
cp $NAME.serial $NAME.p
craf_patch $NAME.p 8 '\002'
info_is 3 "" $NAME.p
craf_expect 3 'version 2 needs a newer craf' $NAME.p info
{
	printf 'AFALGARC\001\000'
	craf_u16 55
	craf_str $drv
	craf_str 'cbc(aes)'
	printf '\040'
	craf_str other
	craf_bytes $iv
} > $NAME.p
info_is 3 "" $NAME.p
craf_expect 3 'unknown key_source "other"' $NAME.p info
craf_expect 3 "cannot open $NAME.none" /dev/null info -in $NAME.none

# -in only
craf_expect 2 'info: takes -in only' $NAME.serial info -out $NAME.o
craf_expect 2 'info: takes -in only' $NAME.serial info -enc-key 1
craf_expect 2 'info: takes -in only' $NAME.serial info -enc-blob $NAME.data
craf_expect 2 'info: takes -in only' $NAME.serial info -cipher-driver $drv
craf_expect 2 'info: takes -in only' $NAME.serial info -cipher-algo 'cbc(aes)'
craf_expect 2 'info: takes -in only' $NAME.serial info -any-driver
craf_expect 2 'unexpected argument "x"' $NAME.serial info x
[ -e $NAME.o ] && fail=y

. test-end.inc
