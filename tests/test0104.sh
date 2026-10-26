#!/bin/bash

echo -n "library     [libkcrypto]: "

. test-preset.inc

# usage: exports <library> <symbol...>: its interface is these, nothing
# else; the symbols the linker defines, which some toolchains export, are
# not the library's
exports () {
	local lib=$1

	shift
	printf '%s\n' "$@" | LC_ALL=C sort > $NAME.ref
	nm -D --defined-only "$lib" |
		awk '$3 !~ /^(_init|_fini|_edata|_end|__bss_start)$/ { print $3 }' |
		LC_ALL=C sort > $NAME.sym || fail=y
	diff -u $NAME.ref $NAME.sym || fail=y
}

fail=n
bin=$(command -v crypto-afalg)
kc=$(dirname "$bin")/libkcrypto.so.0

# The tools take their crypto from libkcrypto only, and none of them
# from the libafalg it replaces or from OpenSSL's libcrypto
for f in crypto-afalg craf libkcrypto.so.0; do
	readelf -d "$(dirname "$bin")/$f" > $NAME.out || fail=y
	if grep -qE 'Shared library: \[lib(afalg|crypto)\.so' $NAME.out; then
		fail=y
	fi
	[ $f = libkcrypto.so.0 ] ||
		grep -qF 'Shared library: [libkcrypto.so.0]' $NAME.out || fail=y
done
readelf -d "$kc" > $NAME.out || fail=y
grep -qF 'Library soname: [libkcrypto.so.0]' $NAME.out || fail=y

# What kcrypto.h declares, as the build used it
exports "$kc" $(sed -n 's/^extern .*[ *]\(kc_[a-z0-9_]*\)(.*$/\1/p' \
	"$(dirname "$bin")/lib/kcrypto.h")

. test-end.inc
