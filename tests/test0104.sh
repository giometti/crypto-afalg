#!/bin/bash

echo -n "library     [libafalg]: "

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
lib=$(dirname "$bin")/libafalg.so.0
kc=$(dirname "$bin")/libkcrypto.so.0

# crypto-afalg takes its AF_ALG layer from the shared libraries
readelf -d "$bin" > $NAME.out || fail=y
grep -qF 'Shared library: [libafalg.so.0]' $NAME.out || fail=y
grep -qF 'Shared library: [libkcrypto.so.0]' $NAME.out || fail=y
readelf -d "$lib" > $NAME.out || fail=y
grep -qF 'Library soname: [libafalg.so.0]' $NAME.out || fail=y
readelf -d "$kc" > $NAME.out || fail=y
grep -qF 'Library soname: [libkcrypto.so.0]' $NAME.out || fail=y

exports "$lib" afalg_accept afalg_bind afalg_key_from_spec afalg_recv \
	afalg_send afalg_set_key afalg_set_op_iv afalg_socket
# What kcrypto.h declares, as the build used it
exports "$kc" $(sed -n 's/^extern .*[ *]\(kc_[a-z0-9_]*\)(.*$/\1/p' \
	"$(dirname "$bin")/lib/kcrypto.h")

. test-end.inc
