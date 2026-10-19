# craf-test.inc - what the craf tests need: a session keyring of the
# test's own, two fixed keys in it, openssl and a driver of cbc(aes).
# Sourced after test-preset.inc; without them the test ends as Skipped.

# Fixed keys and IV: with no MAC, a wrong key passes the padding check
# about once in 256 tries, so a test of it must not depend on chance
CRAF_KEY_GOOD=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
CRAF_KEY_BAD=1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
CRAF_IV=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf

# Skipped, with the reason when there is one
craf_skip () {	# [<reason>]
	echo "Skipped${1:+ ($1)}"
	exit 0
}

# Keys go into an anonymous session keyring, gone when the test ends
keyctl new_session > /dev/null 2>&1 || craf_skip
# The help is captured first: grep -q on a pipe can make it fail by SIGPIPE
crypto-afalg hash -h > $NAME.help 2>&1
grep -q keyserial $NAME.help || craf_skip
type openssl > /dev/null 2>&1 || craf_skip

# <hex> as bytes
craf_bytes () {	# <hex>
	printf "$(printf %s "$1" | sed 's/../\\x&/g')"
}

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

# A string of the header: its length in one byte, then its characters
craf_str () {
	printf "\\$(printf %03o ${#1})%s" "$1"
}

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

# The archive of craf_plain with the good key and the fixed IV, by openssl
craf_fixed_archive () {	# <file> [<driver>]
	{
		craf_header $CRAF_IV $2
		craf_plain |
			openssl enc -aes-256-cbc -K $CRAF_KEY_GOOD -iv $CRAF_IV
	} > $1
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
