/*
 * kc-driver.c - algorithms and drivers the kernel has (libkcrypto)
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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kc-internal.h"
#include "kc-backend.h"

#define PROC_CRYPTO		"/proc/crypto"
#define FIELD_MAX		128	/* CRYPTO_MAX_ALG_NAME */

/* The sizes an entry lists, as bits of proc_entry.sizes */
#define SZ_BLOCK		0x1
#define SZ_IV			0x2
#define SZ_KEY_MIN		0x4
#define SZ_KEY_MAX		0x8
#define SZ_ALL			0xf

/* The fields of an entry of /proc/crypto that name and choose a driver */
struct proc_entry {
	char name[FIELD_MAX];
	char driver[FIELD_MAX];
	char type[32];
	char selftest[16];
	char internal[16];
	long priority;
	size_t block;
	size_t iv_len;
	size_t key_min;
	size_t key_max;
	unsigned int sizes;		/* SZ_* of those listed */
};

/* What a scan of /proc/crypto looks for, and what it found */
struct lookup {
	const char *name;
	char found[FIELD_MAX];
	long priority;
	struct proc_entry entry;	/* the one that matched */
};

/* Copies at most size - 1 bytes and terminates, as strlcpy() */
static void copy(char *dst, const char *src, size_t size)
{
	size_t len = strnlen(src, size - 1);

	memcpy(dst, src, len);
	dst[len] = '\0';
}

/* A size of an entry, stored; its bit back, to tell it was listed */
static unsigned int size_field(const char *val, size_t *size,
			       unsigned int bit)
{
	*size = strtoul(val, NULL, 10);
	return bit;
}

/* The next entry: 1, or 0 at the end of the file, -1 on a read error */
static int read_entry(FILE *f, struct proc_entry *pe)
{
	char line[512], *sep, *val;
	bool any = false;
	size_t len;

	memset(pe, 0, sizeof(*pe));
	while (fgets(line, sizeof(line), f)) {
		len = strlen(line);
		if (len > 0 && line[len - 1] == '\n')
			line[--len] = '\0';
		if (len == 0) {
			if (any)
				return 1;
			continue;
		}
		any = true;
		sep = strchr(line, ':');
		if (!sep)
			continue;
		for (val = sep + 1; *val == ' '; val++)
			;
		while (sep > line && sep[-1] == ' ')
			sep--;
		*sep = '\0';
		if (strcmp(line, "name") == 0)
			copy(pe->name, val, sizeof(pe->name));
		else if (strcmp(line, "driver") == 0)
			copy(pe->driver, val, sizeof(pe->driver));
		else if (strcmp(line, "type") == 0)
			copy(pe->type, val, sizeof(pe->type));
		else if (strcmp(line, "selftest") == 0)
			copy(pe->selftest, val, sizeof(pe->selftest));
		else if (strcmp(line, "internal") == 0)
			copy(pe->internal, val, sizeof(pe->internal));
		else if (strcmp(line, "priority") == 0)
			pe->priority = strtol(val, NULL, 10);
		else if (strcmp(line, "blocksize") == 0)
			pe->sizes |= size_field(val, &pe->block, SZ_BLOCK);
		else if (strcmp(line, "ivsize") == 0)
			pe->sizes |= size_field(val, &pe->iv_len, SZ_IV);
		else if (strcmp(line, "min keysize") == 0)
			pe->sizes |= size_field(val, &pe->key_min, SZ_KEY_MIN);
		else if (strcmp(line, "max keysize") == 0)
			pe->sizes |= size_field(val, &pe->key_max, SZ_KEY_MAX);
	}
	if (ferror(f))
		return -1;
	return any;
}

/*
 * The types of /proc/crypto a socket of the given type takes, as the
 * type masks of the kernel do: an skcipher socket an lskcipher too, and
 * the blkcipher, ablkcipher and givcipher of the kernels before 5.5; a
 * hash socket both kinds of hash. NULL for a type the library does not
 * know.
 */
static const char *const *types_taken(const char *type)
{
	static const char *const skcipher[] = {
		"skcipher", "lskcipher", "blkcipher", "ablkcipher",
		"givcipher", NULL
	};
	static const char *const hash[] = { "ahash", "shash", NULL };

	if (strcmp(type, "skcipher") == 0)
		return skcipher;
	if (strcmp(type, "hash") == 0)
		return hash;
	return NULL;
}

static bool is_taken(const char *const *taken, const char *type)
{
	for (; *taken; taken++)
		if (strcmp(*taken, type) == 0)
			return true;
	return false;
}

/*
 * Each entry of a type in taken goes to match() until it returns true:
 * KC_OK when one did, KC_REFUSED when none did, which the caller says,
 * and KC_FAILED when /proc/crypto cannot be read
 */
static int scan(const char *const *taken,
		bool (*match)(const struct proc_entry *pe, struct lookup *l),
		struct lookup *l, struct kc_error *e)
{
	struct proc_entry pe;
	FILE *f;
	int ret, err;

	f = fopen(PROC_CRYPTO, "r");
	if (!f) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "cannot read %s: %s",
			       PROC_CRYPTO, strerror(err));
	}
	while ((ret = read_entry(f, &pe)) > 0)
		if (is_taken(taken, pe.type) && match(&pe, l))
			break;
	err = errno;
	fclose(f);		/* intentionally ignored */
	if (ret < 0)
		return kc_fail(e, KC_FAILED, err, "cannot read %s: %s",
			       PROC_CRYPTO, strerror(err));
	return ret > 0 ? KC_OK : KC_REFUSED;
}

static bool is_driver(const struct proc_entry *pe, struct lookup *l)
{
	if (strcmp(pe->driver, l->name) != 0)
		return false;
	copy(l->found, pe->name, sizeof(l->found));
	return true;
}

static bool is_algo(const struct proc_entry *pe, struct lookup *l)
{
	return strcmp(pe->name, l->name) == 0;
}

/*
 * What crypto_alg_mod_lookup() takes, the first one among equals: the
 * scan goes on to the end
 */
static bool better(const struct proc_entry *pe, struct lookup *l)
{
	if (strcmp(pe->name, l->name) != 0 ||
	    strcmp(pe->selftest, "passed") != 0 ||
	    strcmp(pe->internal, "no") != 0 ||
	    (l->found[0] != '\0' && pe->priority <= l->priority))
		return false;
	copy(l->found, pe->driver, sizeof(l->found));
	l->priority = pe->priority;
	return false;
}

/* The sizes are the algorithm's, the same for every driver of it */
static bool sizes_of(const struct proc_entry *pe, struct lookup *l)
{
	if (strcmp(pe->name, l->name) != 0 && strcmp(pe->driver, l->name) != 0)
		return false;
	l->entry = *pe;
	return true;
}

static int give(char *dst, size_t size, const char *src, struct kc_error *e)
{
	if (strlen(src) >= size)
		return kc_fail(e, KC_USAGE, ENAMETOOLONG, "no room for \"%s\"",
			       src);
	strcpy(dst, src);
	return kc_ok(e);
}

KC_EXPORT int kc_algo_available(const char *type, const char *name,
				struct kc_error *e)
{
	if (!types_taken(type))
		return kc_fail(e, KC_USAGE, EINVAL,
			       "unknown algorithm type \"%s\"", type);
	return KC_BACKEND->available(type, name, e);
}

KC_EXPORT int kc_driver_algo(const char *type, const char *driver,
			     char *algo, size_t size, struct kc_error *e)
{
	const char *const *taken = types_taken(type);
	struct lookup l = { .name = driver };
	int status;

	if (!taken)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "unknown algorithm type \"%s\"", type);
	status = scan(taken, is_driver, &l, e);
	if (status == KC_REFUSED)
		return kc_fail(e, KC_REFUSED, 0, "%s lists no %s driver \"%s\"",
			       PROC_CRYPTO, type, driver);
	if (status)
		return status;
	return give(algo, size, l.found, e);
}

KC_EXPORT int kc_driver_check(const char *type, const char *driver,
			      const char *algo, struct kc_error *e)
{
	char found[FIELD_MAX];
	int status;

	status = kc_driver_algo(type, driver, found, sizeof(found), e);
	if (status == KC_REFUSED || (!status && strcmp(found, algo) != 0))
		return kc_fail(e, KC_REFUSED, 0,
			       "%s lists no %s driver \"%s\" of %s",
			       PROC_CRYPTO, type, driver, algo);
	return status;
}

KC_EXPORT int kc_algo_listed(const char *type, const char *algo,
			     struct kc_error *e)
{
	const char *const *taken = types_taken(type);
	struct lookup l = { .name = algo };
	int status;

	if (!taken)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "unknown algorithm type \"%s\"", type);
	status = scan(taken, is_algo, &l, e);
	if (status == KC_REFUSED)
		return kc_fail(e, KC_REFUSED, 0,
			       "%s lists no %s algorithm \"%s\"",
			       PROC_CRYPTO, type, algo);
	return status ? status : kc_ok(e);
}

KC_EXPORT int kc_driver_for_algo(const char *type, const char *algo,
				 char *driver, size_t size,
				 struct kc_error *e)
{
	const char *const *taken = types_taken(type);
	struct lookup l = { .name = algo };
	int status;

	if (!taken)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "unknown algorithm type \"%s\"", type);
	status = KC_BACKEND->available(type, algo, e);
	if (status)
		return status;
	if (scan(taken, better, &l, e) == KC_FAILED)
		return KC_FAILED;
	if (l.found[0] == '\0')
		return kc_fail(e, KC_REFUSED, 0,
			       "no driver of %s is listed in %s", algo,
			       PROC_CRYPTO);
	return give(driver, size, l.found, e);
}

KC_EXPORT int kc_cipher_sizes(const char *name, size_t *block,
			      size_t *iv_len, size_t *key_min, size_t *key_max,
			      struct kc_error *e)
{
	struct lookup l = { .name = name };
	int status;

	status = KC_BACKEND->available("skcipher", name, e);
	if (status)
		return status;
	status = scan(types_taken("skcipher"), sizes_of, &l, e);
	if (status == KC_REFUSED)
		return kc_fail(e, KC_REFUSED, 0, "%s lists no skcipher \"%s\"",
			       PROC_CRYPTO, name);
	if (status)
		return status;
	/* An IV of 0 is a mode without one: a missing size is no answer */
	if (l.entry.sizes != SZ_ALL)
		return kc_fail(e, KC_FAILED, 0,
			       "%s lists \"%s\" without its sizes", PROC_CRYPTO,
			       name);
	*block = l.entry.block;
	*iv_len = l.entry.iv_len;
	*key_min = l.entry.key_min;
	*key_max = l.entry.key_max;
	return kc_ok(e);
}
