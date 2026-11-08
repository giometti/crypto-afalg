# craf-format.inc - the archive of craf as the tests build it, and how
# they run craf on it: nothing here needs a keyring, openssl or a driver.
# Sourced after test-preset.inc, by craf-test.inc or by a test that needs
# no more.

# <hex> as bytes
craf_bytes () {	# <hex>
	printf "$(printf %s "$1" | sed 's/../\\x&/g')"
}

# A string of the header: its length in one byte, then its characters
craf_str () {
	printf "\\$(printf %03o ${#1})%s" "$1"
}

# A 16-bit integer, little-endian
craf_u16 () {	# <value>
	printf "\\$(printf %03o $(($1 % 256)))\\$(printf %03o $(($1 / 256)))"
}

# The header of version 1 with <iv>, as the format lays it out: of key
# source serial, or trusted with <blob>
craf_header () {	# <iv in hex> [<driver>] [<blob in hex>]
	local drv=${2:-$driver} blob=$3
	local len=$((46 + ${#drv}))

	if [ -n "$blob" ]; then
		len=$((len + 3 + ${#blob} / 2))
	fi
	printf 'AFALGARC\001\000'
	craf_u16 $len
	craf_str "$drv"
	craf_str 'cbc(aes)'
	printf '\040'
	if [ -n "$blob" ]; then
		craf_str trusted
		craf_bytes $1
		craf_u16 $((${#blob} / 2))
		craf_bytes $blob
	else
		craf_str serial
		craf_bytes $1
	fi
}

# A fixed input: no byte below 0x20 but the last one, a newline
craf_plain () {
	seq -s ' ' 1 1000
}

# craf <arguments> on <input> must exit with <status> and end with
# <reason>: the last line, so that a later check cannot answer for it
craf_expect () {	# <status> <reason> <input> <arguments>...
	local exp=$1 reason=$2 input=$3 rc=0
	shift 3
	craf "$@" < $input > /dev/null 2> $NAME.err || rc=$?
	if [ $rc -ne $exp ] ||
		! grep -qF -e "$reason" <<< "$(tail -n 1 $NAME.err)"; then
		echo "craf $*: exit $rc, $(cat $NAME.err)"
		fail=y
	fi
}

# <file>, with the byte at <offset> replaced by <bytes> (as printf takes them)
craf_patch () {	# <file> <offset> <bytes>
	printf "$3" | dd of=$1 bs=1 seek=$2 conv=notrunc 2> /dev/null
}

# The byte at <offset> of <file> xor <mask>, as printf takes it
craf_xor_byte () {	# <file> <offset> <mask>
	printf '\\%03o' $(($(od -An -tu1 -j$2 -N1 $1) ^ $3))
}
