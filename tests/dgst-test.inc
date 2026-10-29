# dgst-test.inc - what the tests of craf dgst need: openssl, the oracle,
# and sha256 in the kernel. Sourced after test-preset.inc; without them
# the test ends as Skipped.

# Skipped, with the reason
dgst_skip () {	# <reason>
	echo "Skipped ($1)"
	exit 0
}

# Whether the kernel has <hash>; a kc-check that could not tell ends the
# test as a failure, not as a kernel without it
dgst_has () {	# <hash>
	local rc=0

	kc-check available hash "$1" 2> $NAME.kc || rc=$?
	if [ $rc -gt 1 ]; then
		echo "kc-check available hash $1: exit $rc, $(cat $NAME.kc)"
		echo KO!
		exit 1
	fi
	return $rc
}

type openssl > /dev/null 2>&1 || dgst_skip "no openssl"
dgst_has sha256 || dgst_skip "no sha256"

# craf dgst <arguments> must exit with <status> and end with <reason>:
# the last line, so that a later check cannot answer for it
dgst_expect () {	# <status> <reason> <arguments>...
	local exp=$1 reason=$2 rc=0
	shift 2
	craf dgst "$@" < /dev/null > $NAME.out 2> $NAME.err || rc=$?
	if [ $rc -ne $exp ] ||
		! grep -qF -e "$reason" <<< "$(tail -n 1 $NAME.err)"; then
		echo "craf dgst $*: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
}

# craf dgst and openssl dgst, with the same <arguments>, must print the
# same, craf with exit status 0 and nothing on stderr
dgst_same () {	# <arguments>...
	local rc=0
	craf dgst "$@" > $NAME.craf 2> $NAME.err || rc=$?
	openssl dgst "$@" > $NAME.ossl
	if [ $rc -ne 0 ] || [ -s $NAME.err ] || ! cmp -s $NAME.craf $NAME.ossl; then
		echo "craf dgst $*: exit $rc, $(cat $NAME.err $NAME.craf), not $(cat $NAME.ossl)"
		fail=y
	fi
}

# craf dgst <arguments>, with an output that cannot be written, must exit
# with <status> and end with <reason>
dgst_unwritable () {	# <status> <reason> <arguments>...
	local exp=$1 reason=$2 rc=0

	shift 2
	if [ -c /dev/full ] && [ -w /dev/full ]; then
		craf dgst "$@" < /dev/null > /dev/full 2> $NAME.err || rc=$?
	else
		# No /dev/full: a file size limit of 0 makes every write to a
		# file fail, so stderr leaves through a pipe, which it spares
		{ (
			trap '' XFSZ
			ulimit -f 0
			craf dgst "$@" < /dev/null > $NAME.full
		) 2>&1 | cat > $NAME.err; } || rc=$?
	fi
	if [ $rc -ne $exp ] ||
		! grep -qF -e "$reason" <<< "$(tail -n 1 $NAME.err)"; then
		echo "craf dgst $* > <unwritable>: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
}
