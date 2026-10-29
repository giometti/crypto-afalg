#!/bin/bash

echo -n "craf        [dgst]: "

. test-preset.inc
. dgst-test.inc

fail=n
printf abc > $NAME.a
head -c 100000 /dev/urandom > $NAME.b
: > $NAME.empty

# The digest of openssl dgst, line for line: the default hash, whose label
# openssl prints as SHA256, the hashes of the table of labels that the
# kernel has, and one it names as openssl does (sha3)
dgst_same $NAME.a
for h in sha1 sha224 sha256 sha384 sha512 sha3-256 md5 sm3; do
	if dgst_has $h; then
		dgst_same -$h $NAME.a $NAME.b $NAME.empty
	fi
done
dgst_same -sha384 -binary $NAME.b
dgst_same -sha256 -binary -hex $NAME.b

# From stdin
rc=0
craf dgst -sha512 < $NAME.b > $NAME.craf 2> $NAME.err || rc=$?
openssl dgst -sha512 < $NAME.b > $NAME.ossl
if [ $rc -ne 0 ] || ! cmp -s $NAME.craf $NAME.ossl; then
	echo "craf dgst -sha512 < file: exit $rc, $(cat $NAME.err $NAME.craf)"
	fail=y
fi

# The name of the kernel: its own label, no warning
rc=0
craf dgst -digest-algo sha256 $NAME.a > $NAME.craf 2> $NAME.err || rc=$?
if [ $rc -ne 0 ] || [ -s $NAME.err ] ||
	[ "$(cat $NAME.craf)" != "sha256($NAME.a)= $(openssl dgst -sha256 -r $NAME.a | cut -d' ' -f1)" ]; then
	echo "craf dgst -digest-algo sha256: exit $rc, $(cat $NAME.err $NAME.craf)"
	fail=y
fi

# A driver where the name of an algorithm is expected is a wrong usage,
# as a hash option too, which openssl does not take
drv=$(driver_of sha256 shash ahash)
if [ -n "$drv" ] && [ "$drv" != sha256 ]; then
	dgst_expect 2 "-digest-algo \"$drv\" is a driver of sha256, give the name of the algorithm" \
		-digest-algo "$drv" $NAME.a
	if [[ $drv =~ ^[a-z0-9-]+$ ]]; then
		dgst_expect 2 "the hash \"$drv\" is a driver of sha256, give the name of the algorithm" \
			-$drv $NAME.a
	fi
fi

# What the kernel does not have, by that name: could not
dgst_expect 3 'dgst: blake2b512 not available' -blake2b512 $NAME.a
dgst_expect 3 'dgst: nosuchhash not available' -digest-algo nosuchhash $NAME.a

# A directory, and an output that cannot be written: could not
mkdir $NAME.dir
dgst_expect 3 "dgst: cannot read $NAME.dir: Is a directory" $NAME.dir
dgst_unwritable 3 'cannot write output' $NAME.a
dgst_unwritable 3 'cannot write output' -binary $NAME.a

# A file that cannot be read: could not, the others still go
rc=0
craf dgst -sha256 $NAME.nofile $NAME.a > $NAME.craf 2> $NAME.err || rc=$?
if [ $rc -ne 3 ] ||
	! grep -qF "dgst: cannot open $NAME.nofile: No such file or directory" $NAME.err ||
	[ "$(cat $NAME.craf)" != "$(openssl dgst -sha256 $NAME.a)" ]; then
	echo "craf dgst with a missing file: exit $rc, $(cat $NAME.err $NAME.craf)"
	fail=y
fi

# -keyform, as openssl takes it, has no effect on a digest
dgst_expect 0 'craf: warning: -keyform has no effect without -verify' \
	-keyform pem $NAME.a
if [ "$(cat $NAME.out)" != "$(openssl dgst $NAME.a)" ]; then
	echo "craf dgst -keyform pem: $(cat $NAME.out)"
	fail=y
fi

# Wrong usage, exit status 2
dgst_expect 2 '-keyform: "P12" is not PEM or DER' -keyform P12 $NAME.a
dgst_expect 2 'dgst: give -sha256 or -digest-algo, not both' \
	-sha256 -digest-algo sha256 $NAME.a
dgst_expect 2 '-digest-algo: the length must be 1 to 63' -digest-algo '' $NAME.a
dgst_expect 2 'missing value for "-digest-algo"' -digest-algo
dgst_expect 2 '-digest-algo: "sha256 enc=raw" is not the name of a hash' \
	-digest-algo 'sha256 enc=raw' $NAME.a
dgst_expect 2 '-digest-algo: "hash=sha256" is not the name of a hash' \
	-digest-algo hash=sha256 $NAME.a
dgst_expect 2 'unknown option or missing value "-SHA256"' -SHA256 $NAME.a
# An abbreviation, ambiguous or not, and an option with more after it
for opt in -bin -h -he -s -si -v -verif -outx; do
	dgst_expect 2 "unknown option or missing value \"$opt\"" $opt $NAME.a
done
for opt in '-sign x' '-prverify x' '-sigopt x' '-out x' -r -c '-verify x' \
	'-signature x' -list '-engine x' -engine_impl '-passin x' '-xoflen 5' \
	-d -debug '-hmac x' '-mac x' '-macopt x' -fips-fingerprint '-rand x' \
	'-writerand x' '-provider-path x' '-provider x' '-propquery x'; do
	dgst_expect 2 "dgst: ${opt%% *} is not implemented by craf" $opt $NAME.a
done

. test-end.inc
