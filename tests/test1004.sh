#!/bin/bash

echo -n "aes-256-cbc [from-openssl]: "

. test-preset.inc

fail=n
head -c $((1 + $RANDOM % 16384)) < /dev/urandom > $NAME.in
key=$(openssl rand -hex 32)
iv=$(openssl rand -hex 16)
info_save key iv
cat $NAME.in | \
	openssl enc -aes-256-cbc -K $key -iv $iv |
	crypto-afalg decrypt aes-256-cbc -K $key -V $iv > $NAME.out || fail=y
diff -u $NAME.in $NAME.out || fail=y

. test-end.inc
