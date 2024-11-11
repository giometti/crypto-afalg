#!/bin/bash

echo -n "aes-128-cbc [from-openssl]: "

. test-preset.inc

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
key=$(openssl rand -hex 16)
iv=$(openssl rand -hex 16)
info_save key iv
cat $NAME.in | \
	openssl enc -aes-128-cbc -K $key -iv $iv |
	crypto-afalg decrypt aes-128-cbc -K $key -V $iv > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
