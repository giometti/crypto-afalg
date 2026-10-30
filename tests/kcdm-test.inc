# kcdm-test.inc - what the tests of kcdm share. Sourced after
# test-preset.inc

# kcdm <arguments>, with nothing on stdin, must exit with <status> and
# print on stderr exactly the line, or nothing for -
kcdm_expect () {	# <status> <stderr line, or -> <arguments>...
	local exp=$1 line=$2 rc=0

	shift 2
	kcdm "$@" < /dev/null > $NAME.out 2> $NAME.err || rc=$?
	if [ $rc -ne $exp ]; then
		echo "kcdm $*: exit $rc, not $exp: $(cat $NAME.err)"
		fail=y
	elif [ "$line" = - ] && [ -s $NAME.err ]; then
		echo "kcdm $*: $(cat $NAME.err)"
		fail=y
	elif [ "$line" != - ] && [ "$(cat $NAME.err)" != "$line" ]; then
		echo "kcdm $*: $(cat $NAME.err)"
		fail=y
	fi
}

# Whether no device-mapper device has the name, as far as this process
# can see: neither its node nor the name the kernel lists
kcdm_unused () {	# <name>
	[ ! -e /dev/mapper/$1 ] &&
		! grep -qsxF -e "$1" /sys/block/dm-*/dm/name
}
