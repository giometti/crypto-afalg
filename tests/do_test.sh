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

which make 2>/dev/null 1>&2 && make -s --no-print-directory -C ..
export PATH+=":..:."
export LD_LIBRARY_PATH=..

echo -n "executing $test... "
./$test

exit 0
