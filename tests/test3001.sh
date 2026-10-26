#!/bin/bash

echo -n "libkcrypto  [available-driver]: "

. test-preset.inc
. kc-test.inc

if ! test_cbc || ! check-kalgo hash sha256; then
	echo Skipped
	exit 0
fi

fail=n
long=$(printf 'x%.0s' $(seq 64))

# Asked to the kernel: yes, no, a name too long to ask, could not ask
expect 0 - available skcipher 'cbc(aes)'
expect 0 - available hash sha256
expect 1 'kc-check: status=1 errnum=2: bind(): No such file or directory' \
	available skcipher 'nosuch(aes)'
expect 2 'kc-check: status=2 errnum=36: bind(): File name too long' \
	available skcipher "$long"
expect 3 'kc-check: status=3 errnum=24: socket(AF_ALG): Too many open files' \
	exhaust available skcipher 'cbc(aes)'
expect 2 'kc-check: status=2 errnum=22: unknown algorithm type "cipher"' \
	available cipher 'cbc(aes)'

# The bind() above lists the drivers the kernel built for them
# CRAF_TEST_DRIVER: a usable one, where the kernel's own is not (README)
cbc=${CRAF_TEST_DRIVER:-$(driver_of 'cbc(aes)' skcipher lskcipher)}
sha=$(driver_of sha256 ahash shash)
if [ -z "$cbc" ] || [ -z "$sha" ]; then
	echo "no driver of cbc(aes) or sha256 in /proc/crypto"
	fail=y
fi

# A driver of the algorithm, of a type the socket takes
expect 0 - driver skcipher "$cbc" 'cbc(aes)'
expect 0 - driver hash "$sha" sha256
expect 1 "kc-check: status=1 errnum=0: /proc/crypto lists no skcipher driver \"$cbc\" of ecb(aes)" \
	driver skcipher "$cbc" 'ecb(aes)'
expect 1 "kc-check: status=1 errnum=0: /proc/crypto lists no hash driver \"$cbc\" of cbc(aes)" \
	driver hash "$cbc" 'cbc(aes)'
expect 1 "kc-check: status=1 errnum=0: /proc/crypto lists no skcipher driver \"nosuch-driver\" of cbc(aes)" \
	driver skcipher nosuch-driver 'cbc(aes)'
expect 2 'kc-check: status=2 errnum=22: unknown algorithm type "cipher"' \
	driver cipher "$cbc" 'cbc(aes)'
expect 3 'kc-check: status=3 errnum=24: cannot read /proc/crypto: Too many open files' \
	exhaust driver skcipher "$cbc" 'cbc(aes)'

# The algorithm of a driver, and whether a name is one of an algorithm
expect 0 - driver-algo skcipher "$cbc"
[ "$(cat $NAME.got)" = 'cbc(aes)' ] || fail=y
expect 0 - driver-algo hash "$sha"
[ "$(cat $NAME.got)" = sha256 ] || fail=y
expect 1 'kc-check: status=1 errnum=0: /proc/crypto lists no skcipher driver "cbc(aes)"' \
	driver-algo skcipher 'cbc(aes)'
expect 1 "kc-check: status=1 errnum=0: /proc/crypto lists no hash driver \"$cbc\"" \
	driver-algo hash "$cbc"
expect 2 'kc-check: status=2 errnum=22: unknown algorithm type "cipher"' \
	driver-algo cipher "$cbc"
expect 3 'kc-check: status=3 errnum=24: cannot read /proc/crypto: Too many open files' \
	exhaust driver-algo skcipher "$cbc"
expect 0 - algo-listed skcipher 'cbc(aes)'
expect 1 "kc-check: status=1 errnum=0: /proc/crypto lists no skcipher algorithm \"$cbc\"" \
	algo-listed skcipher "$cbc"
expect 1 'kc-check: status=1 errnum=0: /proc/crypto lists no hash algorithm "cbc(aes)"' \
	algo-listed hash 'cbc(aes)'
expect 2 'kc-check: status=2 errnum=22: unknown algorithm type "cipher"' \
	algo-listed cipher 'cbc(aes)'
expect 3 'kc-check: status=3 errnum=24: cannot read /proc/crypto: Too many open files' \
	exhaust algo-listed skcipher 'cbc(aes)'

# The driver the kernel takes, by the rule driver_of restates; the kernel
# is asked first, so a name it does not have is its "no"
expect 0 - driver-for-algo skcipher 'cbc(aes)'
[ "$(cat $NAME.got)" = "$(driver_of 'cbc(aes)' skcipher lskcipher)" ] ||
	fail=y
expect 0 - driver-for-algo hash sha256
[ "$(cat $NAME.got)" = "$sha" ] || fail=y
expect 1 'kc-check: status=1 errnum=2: bind(): No such file or directory' \
	driver-for-algo skcipher 'nosuch(aes)'
room=$(driver_of 'cbc(aes)' skcipher lskcipher | wc -c)
expect 0 - driver-for-algo skcipher 'cbc(aes)' $room
expect 2 "kc-check: status=2 errnum=36: no room for \"$(cat $NAME.got)\"" \
	driver-for-algo skcipher 'cbc(aes)' $((room - 1))
expect 2 'kc-check: status=2 errnum=22: unknown algorithm type "cipher"' \
	driver-for-algo cipher 'cbc(aes)'
expect 3 'kc-check: status=3 errnum=24: socket(AF_ALG): Too many open files' \
	exhaust driver-for-algo skcipher 'cbc(aes)'

. test-end.inc
