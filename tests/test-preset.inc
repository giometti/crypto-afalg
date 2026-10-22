NAME=$(basename $0 .sh)
set -e
set -o pipefail

info_save () {
	rm -f $NAME.info
	for v in "$@" ; do
		eval echo "$v=\$$v" >> $NAME.info
	done
}

check-kalgo () {
	crypto-afalg $1 check-kalgo $2
}

# usage: driver_of <algorithm> <type>...: the driver of the algorithm, of
# one of the types, that the kernel takes: the highest priority among the
# tested, not internal ones /proc/crypto lists, the first one among equals
driver_of () {
	local algo=$1

	shift
	ALGO=$algo TYPES="$*" awk 'BEGIN { RS = ""; FS = "\n" }
	{
		n = d = t = s = x = ""
		p = 0
		for (i = 1; i <= NF; i++) {
			split($i, kv, / *: /)
			if (kv[1] == "name") n = kv[2]
			if (kv[1] == "driver") d = kv[2]
			if (kv[1] == "type") t = kv[2]
			if (kv[1] == "priority") p = kv[2] + 0
			if (kv[1] == "selftest") s = kv[2]
			if (kv[1] == "internal") x = kv[2]
		}
		if (n == ENVIRON["ALGO"] && index(" " ENVIRON["TYPES"] " ",
						  " " t " ") &&
		    s == "passed" && x == "no" &&
		    (best == "" || p > bestp)) {
			best = d
			bestp = p
		}
	}
	END { if (best != "") print best }' /proc/crypto
}

# usage: test_cbc: whether the test can use cbc(aes), setting cbc to the
# name it gives: the driver CRAF_TEST_DRIVER names, for a kernel whose
# preferred driver cannot be used through AF_ALG (README), or else the
# algorithm. A driver named there that the kernel does not have, or that
# is not one of cbc(aes), ends the test as a failure, not as skipped.
test_cbc () {
	if [ -z "$CRAF_TEST_DRIVER" ]; then
		cbc='cbc(aes)'
		check-kalgo encrypt "$cbc"
		return
	fi
	cbc=$CRAF_TEST_DRIVER
	if ! kc-check available skcipher "$cbc" ||
		! kc-check driver skcipher "$cbc" 'cbc(aes)'; then
		echo "CRAF_TEST_DRIVER=$cbc: not a driver of cbc(aes) here"
		echo KO!
		exit 1
	fi
}
