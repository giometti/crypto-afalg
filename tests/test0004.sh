#!/bin/bash

echo -n "aes-128-cbc [rand-key-iv-str]: "

. test-preset.inc

fail=n
key=$(openssl rand -hex 16)
iv=$(openssl rand -hex 16)
echo -n 'Single block msgSecond block msg' > $NAME.in
cat $NAME.in | \
	crypto-afalg encrypt aes-128-cbc -K $key -V $iv | \
	crypto-afalg decrypt aes-128-cbc -K $key -V $iv > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
