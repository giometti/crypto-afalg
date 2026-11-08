# craf-test.inc - what the craf tests need: a session keyring of the
# test's own, two fixed keys in it, openssl and a driver of cbc(aes).
# Sourced after test-preset.inc; without them the test ends as Skipped.

# Fixed keys and IV: with no MAC, a wrong key passes the padding check
# about once in 256 tries, so a test of it must not depend on chance
CRAF_KEY_GOOD=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
CRAF_KEY_BAD=1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
CRAF_IV=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf

# The archive as the tests build it, and how they run craf on it
. craf-format.inc

# Skipped, with the reason when there is one
craf_skip () {	# [<reason>]
	echo "Skipped${1:+ ($1)}"
	exit 0
}

# Keys go into an anonymous session keyring, gone when the test ends
keyctl new_session > /dev/null 2>&1 || craf_skip
key_serial || craf_skip "no keyring keys in libkcrypto"
type openssl > /dev/null 2>&1 || craf_skip

# A user key in <keyring>, the session one by default, its serial on stdout
craf_add_key () {	# <name> <hex> [<keyring>]
	craf_bytes $2 | keyctl padd user $1 ${3:-@s}
}
good=$(craf_add_key $NAME-good $CRAF_KEY_GOOD)
bad=$(craf_add_key $NAME-bad $CRAF_KEY_BAD)

# The cipher_driver field of an archive
craf_driver_of () {	# <file>
	dd if=$1 bs=1 skip=13 count=$(($(od -An -tu1 -j12 -N1 $1))) \
		2> /dev/null
}

# The driver of the tests: CRAF_TEST_DRIVER when set, for a kernel whose
# preferred driver of cbc(aes) cannot be used through AF_ALG; otherwise
# the one craf -cipher-algo takes, which also binds it, so that the
# kernel lists it. A kernel without cbc(aes) at all skips the test, any
# other failure of craf fails it.
if [ -n "$CRAF_TEST_DRIVER" ]; then
	driver=$CRAF_TEST_DRIVER
else
	rc=0
	craf seal -cipher-algo 'cbc(aes)' -enc-key $good < /dev/null \
		> $NAME.probe 2> $NAME.err || rc=$?
	if [ $rc -eq 3 ] &&
		grep -q '^craf: cipher_algo "cbc(aes)" not available' $NAME.err; then
		craf_skip
	fi
	if [ $rc -ne 0 ]; then
		echo "craf seal -cipher-algo: exit $rc, $(cat $NAME.err)"
		echo KO!
		exit 1
	fi
	driver=$(craf_driver_of $NAME.probe)
fi

# The first usable skcipher driver of <algorithm> the kernel lists; one
# built from a template is listed only once something has used it
craf_listed_driver () {	# <algorithm>
	CRAF_ALGO=$1 awk -F ' *: |\n' -v RS= '
		{
			split("", f)
			for (i = 1; i < NF; i += 2)
				f[$i] = $(i + 1)
			if (f["name"] == ENVIRON["CRAF_ALGO"] &&
			    f["type"] ~ /^l?skcipher$/ &&
			    f["selftest"] == "passed" && f["internal"] == "no") {
				print f["driver"]
				exit
			}
		}' /proc/crypto
}

# The archive of craf_plain with the good key and the fixed IV, by openssl
craf_fixed_archive () {	# <file> [<driver>]
	{
		craf_header $CRAF_IV $2
		craf_plain |
			openssl enc -aes-256-cbc -K $CRAF_KEY_GOOD -iv $CRAF_IV
	} > $1
}
