#!/bin/bash

set -e

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "${tmp:?}"' EXIT
export TESTS_TMPDIR=$tmp

for t in $(ls test*.sh | sort -V) ; do
        ./do_test.sh $t
done
echo "all test are OK!"

exit 0
