NAME=$(basename $0 .sh)
set -e
set -o pipefail

info_save () {
	rm -f $NAME.info
	for v in "$@" ; do
		eval echo "$v=\$$v" >> $NAME.info
	done
}

check-kalgo () {
	crypto-afalg $1 check-kalgo $2
}
