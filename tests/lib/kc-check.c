/*
 * kc-check.c - drive libkcrypto from the tests
 *
 * Copyright (C) 2026 Rodolfo Giometti <giometti@enneenne.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include "kcrypto.h"

/* Not a kc_status: the command line of kc-check itself was wrong */
#define EXIT_USAGE		64

#define ARRAY_LEN(a)		(sizeof(a) / sizeof((a)[0]))

static void __attribute__((noreturn)) usage(void)
{
	fprintf(stderr,
		"usage: kc-check [exhaust] <command> <args...>\n"
		"  available <type> <name>\n"
		"  driver <type> <driver> <algo>\n"
		"  key-spec <spec>: prints the serial\n"
		"  hash <name> <key> [<room>]: stdin in pieces of many sizes,\n"
		"    the digest in hex on stdout; <key> is - for none,\n"
		"    hex:<bytes> or spec:<spec>\n"
		"  hash-after <name> <room> final|update: after a final with\n"
		"    room bytes, the status of one more call\n"
		"exhaust: no file descriptor left before the command\n"
		"exit status: the kc_status, %d for a wrong command line\n",
		EXIT_USAGE);
	exit(EXIT_USAGE);
}

/*
 * Takes every free file descriptor under a limit lowered for this, so
 * that the next open fails; they go back before the exit, which
 * AddressSanitizer needs some for
 */
#define FD_LIMIT		64

static struct rlimit saved;
static int taken[FD_LIMIT];
static int ntaken;

static void exhaust(void)
{
	struct rlimit low;
	int fd;

	if (getrlimit(RLIMIT_NOFILE, &saved) < 0) {
		perror("kc-check: getrlimit");
		exit(EXIT_USAGE);
	}
	low = saved;
	if (low.rlim_cur > FD_LIMIT)
		low.rlim_cur = FD_LIMIT;
	if (setrlimit(RLIMIT_NOFILE, &low) < 0) {
		perror("kc-check: setrlimit");
		exit(EXIT_USAGE);
	}
	while (ntaken < FD_LIMIT && (fd = dup(STDERR_FILENO)) >= 0)
		taken[ntaken++] = fd;
}

static void release(void)
{
	if (ntaken == 0)
		return;
	while (ntaken > 0)
		close(taken[--ntaken]);	/* intentionally ignored */
	setrlimit(RLIMIT_NOFILE, &saved);	/* intentionally ignored */
}

/*
 * The sizes stdin is read in, to cross every block boundary and the size
 * the library passes to the kernel at once
 */
#define PIECE_MAX		20000

static const size_t pieces[] = {
	15, 17, 1, 7, 16, 63, 64, 65, 4096, 3, PIECE_MAX
};

static size_t read_piece(unsigned char *buf, size_t *i)
{
	return fread(buf, 1, pieces[(*i)++ % ARRAY_LEN(pieces)], stdin);
}

/* Exactly two hex digits a byte */
static size_t parse_hex(const char *s, unsigned char *buf, size_t size)
{
	size_t len = strlen(s) / 2, i;
	unsigned int byte;

	if (strlen(s) % 2 || len > size)
		usage();
	for (i = 0; i < len; i++) {
		if (!isxdigit((unsigned char) s[2 * i]) ||
		    !isxdigit((unsigned char) s[2 * i + 1]) ||
		    sscanf(s + 2 * i, "%2x", &byte) != 1)
			usage();
		buf[i] = byte;
	}
	return len;
}

/* "-", "hex:<bytes>" or "spec:<spec>": NULL for none */
static int make_key(const char *arg, struct kc_key **k, struct kc_error *e)
{
	unsigned char buf[1024];

	*k = NULL;
	if (strcmp(arg, "-") == 0)
		return KC_OK;
	if (strncmp(arg, "hex:", 4) == 0)
		return kc_key_raw(k, buf, parse_hex(arg + 4, buf, sizeof(buf)),
				  e);
	if (strncmp(arg, "spec:", 5) == 0)
		return kc_key_spec(k, arg + 5, e);
	usage();
}

static void print_hex(const unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

static int key_spec(const char *spec, struct kc_error *e)
{
	struct kc_key *k;
	int status;

	status = kc_key_spec(&k, spec, e);
	if (status)
		return status;
	printf("%d\n", kc_key_serial(k));
	kc_key_free(k);
	return KC_OK;
}

static int hash(const char *name, const char *key, size_t room,
		struct kc_error *e)
{
	unsigned char buf[PIECE_MAX], md[KC_HASH_MAX];
	struct kc_hash *h = NULL;
	struct kc_key *k;
	size_t n, i = 0;
	int status;

	if (room > sizeof(md))
		usage();
	status = make_key(key, &k, e);
	if (!status)
		status = kc_hash_open(&h, name, k, e);
	while (!status && (n = read_piece(buf, &i)) > 0)
		status = kc_hash_update(h, buf, n, e);
	if (!status)
		status = kc_hash_final(h, md, &room, e);
	if (!status)
		print_hex(md, room);
	kc_hash_free(h);
	kc_key_free(k);
	return status;
}

static int hash_after(const char *name, size_t room, const char *then,
		      struct kc_error *e)
{
	unsigned char md[KC_HASH_MAX];
	struct kc_hash *h;
	int status;

	if (room > sizeof(md) ||
	    (strcmp(then, "final") && strcmp(then, "update")))
		usage();
	status = kc_hash_open(&h, name, NULL, e);
	if (status)
		return status;
	kc_hash_final(h, md, &room, e);		/* intentionally ignored */
	room = sizeof(md);
	if (strcmp(then, "final") == 0)
		status = kc_hash_final(h, md, &room, e);
	else
		status = kc_hash_update(h, "x", 1, e);
	kc_hash_free(h);
	return status;
}

/*
 * The status is the exit status; a failure also prints what the library
 * filled in, which must agree with what it returned
 */
static int report(int status, const struct kc_error *e)
{
	if ((int) e->status != status) {
		fprintf(stderr, "kc-check: returned %d, filled in %d\n",
			status, e->status);
		return EXIT_USAGE;
	}
	if (status != KC_OK)
		fprintf(stderr, "kc-check: status=%d errnum=%d: %s\n",
			status, e->errnum, e->msg);
	return status;
}

int main(int argc, char *argv[])
{
	struct kc_error e;
	int status;

	/* A status left from before must be overwritten, KC_OK too */
	memset(&e, 0x5a, sizeof(e));
	if (argc > 1 && strcmp(argv[1], "exhaust") == 0) {
		argc--;
		argv++;
		exhaust();
	}
	if (argc < 2)
		usage();

	if (strcmp(argv[1], "available") == 0 && argc == 4)
		status = kc_algo_available(argv[2], argv[3], &e);
	else if (strcmp(argv[1], "driver") == 0 && argc == 5)
		status = kc_driver_check(argv[2], argv[3], argv[4], &e);
	else if (strcmp(argv[1], "key-spec") == 0 && argc == 3)
		status = key_spec(argv[2], &e);
	else if (strcmp(argv[1], "hash-after") == 0 && argc == 5)
		status = hash_after(argv[2], strtoul(argv[3], NULL, 10),
				    argv[4], &e);
	else if (strcmp(argv[1], "hash") == 0 && (argc == 4 || argc == 5))
		status = hash(argv[2], argv[3],
			      argc == 5 ? strtoul(argv[4], NULL, 10) :
			      KC_HASH_MAX, &e);
	else
		usage();
	release();

	return report(status, &e);
}
