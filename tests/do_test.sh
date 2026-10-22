#!/bin/bash

if [ $# -lt 1 ] ; then
        echo "usage: $0 <num>" >&2
        exit 1
fi
n=$1
if [ -x test$n.sh ] ; then
        test=test$n.sh
else
        test=$n
fi
if [ ! -x $test ] ; then
        echo "cannot find executable $test" >&2
        exit 1
fi

set -e

tests=$(cd "$(dirname "$0")" && pwd)
top=$(dirname "$tests")
path=$(realpath -- "$test")

# Build and run out of the source tree; do_all_tests.sh shares one
# directory with every test through TESTS_TMPDIR and removes it itself
if [ -n "$TESTS_TMPDIR" ]; then
	tmp=$TESTS_TMPDIR
else
	tmp=$(mktemp -d) || exit 1
	trap 'rm -rf "${tmp:?}"' EXIT
fi
mkdir -p "$tmp/build" "$tmp/run"

# A copy of the sources, not VPATH: make would take objects and binary
# already built in the source tree as up to date and skip $tmp/build.
# With -p the mtimes are kept, so the tests after the first rebuild nothing.
# The Makefile is the source tree's one, so the version is that tree's
cp -p "$top"/*.c "$top"/*.h "$tmp/build/"
mkdir -p "$tmp/build/lib/backend" "$tmp/build/tests/lib"
cp -p "$top"/lib/*.[ch] "$tmp/build/lib/"
cp -p "$top"/lib/backend/*.[ch] "$tmp/build/lib/backend/"
cp -p "$top"/tests/lib/*.c "$tmp/build/tests/lib/"
make -s --no-print-directory -C "$tmp/build" -f "$top/Makefile" all kc-check
# The tests source test-preset.inc and test-end.inc by bare name: the
# shell finds them through PATH
export PATH="$tmp/build:$tests:$PATH"
export LD_LIBRARY_PATH="$tmp/build"
export SRCDIR=$top

# A tool the build did not make would be taken from the rest of PATH
for tool in crypto-afalg craf kc-check; do
	if [ "$(command -v $tool)" != "$tmp/build/$tool" ]; then
		echo "$tool: not built in $tmp/build" >&2
		exit 1
	fi
done

echo -n "executing $test... "
cd "$tmp/run"
"$path"

exit 0
