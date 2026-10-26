# enc-test.inc - what the tests of craf enc need: an openssl that writes
# enc -pbkdf2 files, as the oracle, and cbc(aes) in the kernel. Sourced
# after test-preset.inc; without them the test ends as Skipped.

# Skipped, with the reason
enc_skip () {	# <reason>
	echo "Skipped ($1)"
	exit 0
}

type openssl > /dev/null 2>&1 || enc_skip "no openssl"
openssl enc -help 2>&1 | grep -q -e '-pbkdf2' ||
	enc_skip "an openssl without enc -pbkdf2"
test_cbc || enc_skip "no cbc(aes)"

# CRAF_TEST_DRIVER, where the kernel's own driver of cbc(aes) cannot be
# used through AF_ALG; empty, the kernel chooses
drv=()
if [ -n "$CRAF_TEST_DRIVER" ]; then
	drv=(-cipher-driver "$CRAF_TEST_DRIVER")
fi

# craf enc <arguments> on <input> must exit with <status> and end with
# <reason>: the last line, so that a later check cannot answer for it
enc_expect () {	# <status> <reason> <input> <arguments>...
	local exp=$1 reason=$2 input=$3 rc=0
	shift 3
	craf enc "$@" < $input > /dev/null 2> $NAME.err || rc=$?
	if [ $rc -ne $exp ] ||
		! grep -qF -e "$reason" <<< "$(tail -n 1 $NAME.err)"; then
		echo "craf enc $*: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
}
