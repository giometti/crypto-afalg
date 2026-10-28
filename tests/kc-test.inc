# What the tests of libkcrypto share; sourced after test-preset.inc

# usage: expect <status> <stderr line, or - for none> <kc-check args...>:
# kc-check, with nothing on stdin, exits with the status and prints the
# line, or nothing
expect () {
	local want=$1 line=$2 rc=0

	shift 2
	kc-check "$@" < /dev/null > $NAME.got 2> $NAME.err || rc=$?
	if [ $rc -ne $want ]; then
		echo "kc-check $*: exit $rc, not $want: $(cat $NAME.err)"
		fail=y
	elif [ "$line" = - ] && [ -s $NAME.err ]; then
		echo "kc-check $*: $(cat $NAME.err)"
		fail=y
	elif [ "$line" != - ] && ! grep -qxF -e "$line" $NAME.err; then
		echo "kc-check $*: $(cat $NAME.err)"
		fail=y
	fi
}

# usage: flip <file> <offset>: inverts the lowest bit of the byte at
# offset, so that the file changes whatever the byte was
flip () {
	local b

	b=$(od -An -tu1 -j $2 -N1 $1)
	printf "\\$(printf %03o $((b ^ 1)))" |
		dd of=$1 bs=1 seek=$2 conv=notrunc 2> /dev/null
}
