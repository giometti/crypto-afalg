#!/bin/bash

set -e

for t in $(ls test*.sh | sort -V) ; do
        ./do_test.sh $t
done
echo "all test are OK!"

exit 0
