#!/bin/bash

echo -n "craf        [usage-driver]: "

. test-preset.inc
. craf-test.inc

fail=n
head -c 3000 /dev/urandom > $NAME.in
craf seal -cipher-driver $driver -enc-key $good \
	< $NAME.in > $NAME.craf || fail=y

# Help on stdout with status 0, also for a command
craf -help > $NAME.out 2> $NAME.err || fail=y
grep -q '^usage: craf' $NAME.out || fail=y
[ -s $NAME.err ] && fail=y
craf seal -help > $NAME.out || fail=y
grep -q '^usage: craf' $NAME.out || fail=y
craf -version > $NAME.out || fail=y
grep -q '^craf v' $NAME.out || fail=y

# Wrong usage; without arguments, the help on stderr
rc=0
craf > $NAME.out 2> $NAME.err || rc=$?
[ $rc -eq 2 ] || fail=y
grep -q '^usage: craf' $NAME.err || fail=y
[ -s $NAME.out ] && fail=y
craf_expect 2 'unknown command "foo"' $NAME.in foo
craf_expect 2 'unknown option' $NAME.in seal -nope
craf_expect 2 'unexpected argument "extra"' $NAME.craf \
	unseal -enc-key $good extra
craf_expect 2 '-cipher-driver or -cipher-algo is required' $NAME.in \
	seal -enc-key $good
craf_expect 2 'not both' $NAME.in \
	seal -cipher-driver $driver -cipher-algo 'cbc(aes)' -enc-key $good
craf_expect 2 '-cipher-algo is for seal only' $NAME.craf \
	unseal -cipher-algo 'cbc(aes)' -enc-key $good
craf_expect 2 'not both' $NAME.craf \
	unseal -cipher-driver $driver -any-driver -enc-key $good
craf_expect 2 'is for unseal only' $NAME.in \
	seal -any-driver -cipher-driver $driver -enc-key $good
craf_expect 2 'unsupported "ecb(aes)"' $NAME.in \
	seal -cipher-algo 'ecb(aes)' -enc-key $good
craf_expect 2 'names an algorithm, not a driver' $NAME.in \
	seal -cipher-driver 'cbc(aes)' -enc-key $good
craf_expect 2 'the length must be 1 to 63' $NAME.in \
	seal -cipher-driver $(printf 'x%.0s' {1..64}) -enc-key $good

# A missing key is wrong usage, whatever the input
craf_expect 2 'unseal: -enc-key is required' $NAME.in unseal

# The same file as input and output is refused before it is truncated
cp $NAME.craf $NAME.same
craf_expect 2 'the input and the output are the same file' $NAME.in \
	unseal -in $NAME.same -out $NAME.same -enc-key $good
cmp $NAME.craf $NAME.same || fail=y

# A driver of another algorithm
ecb=$(craf_listed_driver 'ecb(aes)')
if [ -n "$ecb" ]; then
	craf_expect 2 "is a driver of ecb(aes), not cbc(aes)" $NAME.in \
		seal -cipher-driver $ecb -enc-key $good
	craf_expect 2 "is a driver of ecb(aes), not cbc(aes)" $NAME.craf \
		unseal -cipher-driver $ecb -enc-key $good
else
	echo -n "(no ecb(aes) listed) "
fi

# unseal takes a driver from the command line instead of the header's
cp $NAME.craf $NAME.other
craf_patch $NAME.other 13 'Z'
craf unseal -cipher-driver $driver -enc-key $good \
	< $NAME.other > $NAME.out || fail=y
cmp $NAME.in $NAME.out || fail=y

# What could not be done
craf_expect 3 'not available' $NAME.in \
	seal -cipher-driver no-such-driver -enc-key $good
craf_expect 3 'not available' $NAME.other \
	unseal -cipher-driver no-such-driver -enc-key $good
craf_expect 3 'cannot open' $NAME.in \
	unseal -in $NAME.missing -enc-key $good
craf_expect 3 'cannot open' $NAME.in \
	seal -out $NAME.missing/x -cipher-driver $driver -enc-key $good

# -cipher-algo takes the highest priority among the tested drivers that
# are not internal, the first among equals: the rule of the kernel's
# __crypto_alg_lookup() as read in its sources, restated here in awk. It
# checks craf's reading of /proc/crypto against that rule, not what the
# kernel actually chooses. Not where the preferred driver is unusable.
if [ -z "$CRAF_TEST_DRIVER" ]; then
	craf seal -cipher-algo 'cbc(aes)' -enc-key $good \
		< $NAME.in > $NAME.algo || fail=y
	rule=$(awk -F ' *: |\n' -v RS= '
		{
			split("", f)
			for (i = 1; i < NF; i += 2)
				f[$i] = $(i + 1)
			if (f["name"] == "cbc(aes)" &&
			    f["type"] ~ /^l?skcipher$/ &&
			    f["selftest"] == "passed" && f["internal"] == "no" &&
			    (drv == "" || f["priority"] + 0 > prio)) {
				drv = f["driver"]
				prio = f["priority"] + 0
			}
		}
		END { print drv }' /proc/crypto)
	[ -n "$rule" ] || fail=y
	[ "$(craf_driver_of $NAME.algo)" = "$rule" ] || fail=y
	craf unseal -enc-key $good < $NAME.algo > $NAME.out || fail=y
	cmp $NAME.in $NAME.out || fail=y
else
	echo -n "(CRAF_TEST_DRIVER set) "
fi

# A failed unseal keeps its -out, as it would stdout
cp $NAME.craf $NAME.bad
printf 'x' >> $NAME.bad
craf_expect 1 'wrong final block length' $NAME.in \
	unseal -in $NAME.bad -out $NAME.res -enc-key $good
[ -f $NAME.res ] || fail=y

# With stderr closed, no message reaches the output file
rc=0
craf unseal -in $NAME.in -out $NAME.res2 -enc-key $good 2>&- || rc=$?
[ $rc -eq 1 ] || fail=y
[ -s $NAME.res2 ] && fail=y

. test-end.inc
