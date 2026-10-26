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
#include <keyutils.h>
#include <linux/if_alg.h>
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
		"  driver-algo <type> <driver>: prints its algorithm\n"
		"  algo-listed <type> <algo>\n"
		"  driver-for-algo <type> <algo> [<room>]: prints the driver\n"
		"  key-spec <spec>: prints the serial\n"
		"  key-serial: 0 if the library takes keyring keys, 1 if not\n"
		"  hash <name> <key> [<room>]: stdin in pieces of many sizes,\n"
		"    the digest in hex on stdout; <key> is - for none,\n"
		"    hex:<bytes>, spec:<spec> or blob:<trusted key blob>\n"
		"  hash-after <name> <room> final|update: after a final with\n"
		"    room bytes, the status of one more call\n"
		"  cipher enc|dec <name> <key> <iv>: stdin in pieces of many\n"
		"    sizes, the result on stdout; <iv> in hex\n"
		"  cipher-after enc|dec <name> <key> <iv>: after a final, the\n"
		"    status of one more update\n"
		"  blob-unload <blob> <name>: the status of a cipher opened\n"
		"    with the key once unloaded, twice\n"
		"  blob-gone <blob>: the status of an unload once the key is\n"
		"    gone already\n"
		"  blob-twice <blob>: the status of a second key of the same\n"
		"    blob, the first one still loaded\n"
		"  pbkdf2 <hmac> <pass> <salt> <iter> <len>: in hex\n"
		"  header: the salt of the openssl enc header on stdin\n"
		"  header-make <salt>: the header on stdout\n"
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

/* "-", "hex:<bytes>", "spec:<spec>" or "blob:<bytes>": NULL for none */
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
	if (strncmp(arg, "blob:", 5) == 0)
		return kc_key_blob(k, buf, parse_hex(arg + 5, buf, sizeof(buf)),
				   e);
	usage();
}

static void print_hex(const unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

/* What kc-check writes is all there, or it is no check */
static void put(const void *buf, size_t len)
{
	if (fwrite(buf, 1, len, stdout) != len) {
		perror("kc-check: write");
		exit(EXIT_USAGE);
	}
}

static void *xmalloc(size_t size)
{
	void *p = malloc(size);

	if (!p) {
		perror("kc-check: malloc");
		exit(EXIT_USAGE);
	}
	return p;
}

static int driver_algo(const char *type, const char *driver,
		       struct kc_error *e)
{
	char algo[128];
	int status;

	status = kc_driver_algo(type, driver, algo, sizeof(algo), e);
	if (!status)
		printf("%s\n", algo);
	return status;
}

/* Exactly the room given, for AddressSanitizer */
static int driver_for_algo(const char *type, const char *algo, size_t room,
			   struct kc_error *e)
{
	char *driver = xmalloc(room);
	int status;

	status = kc_driver_for_algo(type, algo, driver, room, e);
	if (!status)
		printf("%s\n", driver);
	free(driver);
	return status;
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

/*
 * Filled in here: the library answers with no kc_status. Its answer must
 * be what the headers of this build say, which are the library's too.
 */
static int key_serial(struct kc_error *e)
{
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
	const int headers = 1;
#else
	const int headers = 0;
#endif

	if (kc_key_serial_supported() != headers) {
		fprintf(stderr,
			"kc-check: the library says %d, the headers %d\n",
			kc_key_serial_supported(), headers);
		exit(EXIT_USAGE);
	}
	e->status = headers ? KC_OK : KC_REFUSED;
	e->errnum = 0;
	snprintf(e->msg, sizeof(e->msg), "%s",
		 e->status ? "no keyring keys" : "");
	return e->status;
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

static int cipher(const char *dir, const char *name, const char *key,
		  const char *iv_hex, struct kc_error *e)
{
	unsigned char buf[PIECE_MAX], iv[64], *out;
	struct kc_cipher *c = NULL;
	struct kc_key *k;
	size_t iv_len, n, len, i = 0;
	int status;

	if (strcmp(dir, "enc") && strcmp(dir, "dec"))
		usage();
	iv_len = parse_hex(iv_hex, iv, sizeof(iv));
	status = make_key(key, &k, e);
	if (!status)
		status = kc_cipher_open(&c, name, k, strcmp(dir, "enc") == 0,
					iv, iv_len, e);
	/* Exactly the room the library asks for, for AddressSanitizer */
	while (!status && (n = read_piece(buf, &i)) > 0) {
		out = xmalloc(n + iv_len);
		status = kc_cipher_update(c, buf, n, out, &len, e);
		if (!status)
			put(out, len);
		free(out);
	}
	/* What a refusing final gives goes out too, as the tools write it */
	if (!status) {
		out = xmalloc(iv_len);
		status = kc_cipher_final(c, out, &len, e);
		put(out, len);
		free(out);
	}
	kc_cipher_free(c);
	kc_key_free(k);
	return status;
}

/* The key freed once the cipher is open, which must not need it */
static int cipher_after(const char *dir, const char *name, const char *key,
			const char *iv_hex, struct kc_error *e)
{
	unsigned char iv[64], out[2 * KC_BLOCK_MAX];
	struct kc_cipher *c;
	struct kc_key *k;
	size_t iv_len, len;
	int status;

	if (strcmp(dir, "enc") && strcmp(dir, "dec"))
		usage();
	iv_len = parse_hex(iv_hex, iv, sizeof(iv));
	status = make_key(key, &k, e);
	if (status)
		return status;
	status = kc_cipher_open(&c, name, k, strcmp(dir, "enc") == 0, iv,
				iv_len, e);
	kc_key_free(k);
	if (status)
		return status;
	kc_cipher_final(c, out, &len, e);	/* intentionally ignored */
	status = kc_cipher_update(c, "x", 1, out, &len, e);
	kc_cipher_free(c);
	return status;
}

/* An unloaded key is out of the keyring: a second unload has nothing to do */
static int blob_unload(const char *blob, const char *name, struct kc_error *e)
{
	unsigned char iv[16] = { 0 };
	struct kc_cipher *c = NULL;
	struct kc_key *k;
	char arg[2048];
	int status;

	snprintf(arg, sizeof(arg), "blob:%s", blob);
	status = make_key(arg, &k, e);
	if (!status)
		status = kc_key_unload(k, e);
	if (!status)
		status = kc_key_unload(k, e);
	if (!status)
		status = kc_cipher_open(&c, name, k, 1, iv, sizeof(iv), e);
	kc_cipher_free(c);
	kc_key_free(k);
	return status;
}

/* The key taken out of the keyring behind the library's back */
static int blob_gone(const char *blob, struct kc_error *e)
{
	struct kc_key *k;
	char arg[2048];
	int status;

	snprintf(arg, sizeof(arg), "blob:%s", blob);
	status = make_key(arg, &k, e);
	if (status)
		return status;
	if (keyctl_invalidate(kc_key_serial(k)) < 0) {
		perror("kc-check: keyctl_invalidate");
		exit(EXIT_USAGE);
	}
	status = kc_key_unload(k, e);
	kc_key_free(k);
	return status;
}

static int blob_twice(const char *blob, struct kc_error *e)
{
	struct kc_key *k1, *k2 = NULL;
	char arg[2048];
	int status;

	snprintf(arg, sizeof(arg), "blob:%s", blob);
	status = make_key(arg, &k1, e);
	if (status)
		return status;
	status = make_key(arg, &k2, e);
	kc_key_free(k2);
	kc_key_free(k1);
	return status;
}

static int pbkdf2(const char *hmac, const char *pass_hex,
		  const char *salt_hex, const char *iter, const char *len,
		  struct kc_error *e)
{
	unsigned char pass[1024], salt[1024], out[1024];
	size_t pass_len, salt_len, out_len;
	int status;

	pass_len = parse_hex(pass_hex, pass, sizeof(pass));
	salt_len = parse_hex(salt_hex, salt, sizeof(salt));
	out_len = strtoul(len, NULL, 10);
	if (out_len > sizeof(out))
		usage();
	status = kc_pbkdf2(hmac, pass, pass_len, salt, salt_len,
			   strtoul(iter, NULL, 10), out, out_len, e);
	if (!status)
		print_hex(out, out_len);
	return status;
}

static int header(struct kc_error *e)
{
	uint8_t buf[KC_OPENSSL_HEADER_LEN], salt[KC_OPENSSL_SALT_LEN];
	int status;

	status = kc_openssl_header(buf, fread(buf, 1, sizeof(buf), stdin),
				   salt, e);
	if (!status)
		print_hex(salt, sizeof(salt));
	return status;
}

static int header_make(const char *salt_hex)
{
	uint8_t buf[KC_OPENSSL_HEADER_LEN], salt[KC_OPENSSL_SALT_LEN];

	if (parse_hex(salt_hex, salt, sizeof(salt)) != sizeof(salt))
		usage();
	kc_openssl_header_make(buf, salt);
	put(buf, sizeof(buf));
	return KC_OK;
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
	else if (strcmp(argv[1], "driver-algo") == 0 && argc == 4)
		status = driver_algo(argv[2], argv[3], &e);
	else if (strcmp(argv[1], "algo-listed") == 0 && argc == 4)
		status = kc_algo_listed(argv[2], argv[3], &e);
	else if (strcmp(argv[1], "driver-for-algo") == 0 &&
		 (argc == 4 || argc == 5))
		status = driver_for_algo(argv[2], argv[3], argc == 5 ?
					 strtoul(argv[4], NULL, 10) :
					 KC_NAME_MAX + 1, &e);
	else if (strcmp(argv[1], "key-spec") == 0 && argc == 3)
		status = key_spec(argv[2], &e);
	else if (strcmp(argv[1], "key-serial") == 0 && argc == 2)
		status = key_serial(&e);
	else if (strcmp(argv[1], "hash-after") == 0 && argc == 5)
		status = hash_after(argv[2], strtoul(argv[3], NULL, 10),
				    argv[4], &e);
	else if (strcmp(argv[1], "blob-unload") == 0 && argc == 4)
		status = blob_unload(argv[2], argv[3], &e);
	else if (strcmp(argv[1], "blob-gone") == 0 && argc == 3)
		status = blob_gone(argv[2], &e);
	else if (strcmp(argv[1], "blob-twice") == 0 && argc == 3)
		status = blob_twice(argv[2], &e);
	else if (strcmp(argv[1], "pbkdf2") == 0 && argc == 7)
		status = pbkdf2(argv[2], argv[3], argv[4], argv[5], argv[6],
				&e);
	else if (strcmp(argv[1], "header") == 0 && argc == 2)
		status = header(&e);
	else if (strcmp(argv[1], "header-make") == 0 && argc == 3) {
		status = header_make(argv[2]);
		e.status = KC_OK;
	} else if (strcmp(argv[1], "cipher") == 0 && argc == 6)
		status = cipher(argv[2], argv[3], argv[4], argv[5], &e);
	else if (strcmp(argv[1], "cipher-after") == 0 && argc == 6)
		status = cipher_after(argv[2], argv[3], argv[4], argv[5], &e);
	else if (strcmp(argv[1], "hash") == 0 && (argc == 4 || argc == 5))
		status = hash(argv[2], argv[3],
			      argc == 5 ? strtoul(argv[4], NULL, 10) :
			      KC_HASH_MAX, &e);
	else
		usage();
	release();

	return report(status, &e);
}
