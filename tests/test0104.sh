#!/bin/bash

echo -n "library     [libafalg]: "

. test-preset.inc

fail=n
bin=$(command -v crypto-afalg)
lib=$(dirname "$bin")/libafalg.so.0

# crypto-afalg takes its AF_ALG layer from the shared library
readelf -d "$bin" > $NAME.out || fail=y
grep -qF 'Shared library: [libafalg.so.0]' $NAME.out || fail=y
readelf -d "$lib" > $NAME.out || fail=y
grep -qF 'Library soname: [libafalg.so.0]' $NAME.out || fail=y

# Its interface is the afalg_* functions, and nothing else; the symbols
# the linker defines, which some toolchains export, are not the library's
printf '%s\n' afalg_accept afalg_bind afalg_key_from_spec afalg_recv \
	afalg_send afalg_set_key afalg_set_op_iv afalg_socket |
	LC_ALL=C sort > $NAME.ref
nm -D --defined-only "$lib" |
	awk '$3 !~ /^(_init|_fini|_edata|_end|__bss_start)$/ { print $3 }' |
	LC_ALL=C sort > $NAME.sym || fail=y
diff -u $NAME.ref $NAME.sym || fail=y

. test-end.inc
