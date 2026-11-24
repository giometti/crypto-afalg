#!/bin/bash

echo -n "build       [32-bit]: "

. test-preset.inc

# usage: probe <cc...>: whether the compiler has a size_t of 32 bits and
# the headers of the build, one it lacks being no defect of the code
probe () {
	{
		printf '#include <%s>\n' stdio.h keyutils.h linux/if_alg.h \
			linux/dm-ioctl.h
		echo '_Static_assert(sizeof(size_t) == 4, "size_t");'
	} | "$@" -x c -fsyntax-only - 2> /dev/null
}

# Every object, compiled as the Makefile compiles it, by a compiler whose
# size_t is 32 bits: what it diagnoses there only (a format, a cast, a
# static assertion) fails here, where the native build of the suite
# cannot see it. Nothing is linked or run.
tried="arm-linux-gnueabihf-gcc, i686-linux-gnu-gcc, gcc -m32"
cc32=
for cc in arm-linux-gnueabihf-gcc i686-linux-gnu-gcc 'gcc -m32'; do
	if probe $cc; then
		cc32=$cc
		break
	fi
done
if [ -z "$cc32" ]; then
	echo "Skipped (no 32-bit C compiler: $tried)"
	exit 0
fi

fail=n
src=$NAME.src
rm -rf "${NAME:?}.src"
mkdir -p $src/lib/backend $src/tests/lib
cp $SRCDIR/*.c $SRCDIR/*.h $src/
cp $SRCDIR/lib/*.[ch] $src/lib/
cp $SRCDIR/lib/backend/*.[ch] $src/lib/backend/
cp $SRCDIR/tests/lib/*.c $src/tests/lib/
objs=$(cd $src && ls *.c lib/*.c lib/backend/*.c tests/lib/*.c |
	sed 's/\.c$/.o/')

# Only the objects: a 32-bit libkeyutils to link with is seldom there.
# MAKEFLAGS emptied, so that a CFLAGS or -i given to make tests cannot
# take -Werror away, and its CC or ASAN stay out.
rc=0
MAKEFLAGS= make -s -k --no-print-directory -C $src -f $SRCDIR/Makefile \
	CC="$cc32" ASAN= $objs > $NAME.err 2>&1 || rc=$?
if [ $rc -ne 0 ]; then
	echo "$cc32: exit $rc"
	grep -E ': (error|fatal error|warning|note: in expansion of macro)' \
		$NAME.err ||
		cat $NAME.err
	fail=y
fi

. test-end.inc
