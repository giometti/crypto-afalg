#!/bin/bash

echo -n "aes-128-cbc [rand-key-iv-file]: "

. test-preset.inc

fail=n
openssl rand 16 > $NAME.key
openssl rand 16 > $NAME.iv
echo -n 'Single block msgSecond block msg' > $NAME.in
cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc -k $NAME.key -v $NAME.iv | \
	crypto-afalg decrypt aes-128-cbc -k $NAME.key -v $NAME.iv > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
