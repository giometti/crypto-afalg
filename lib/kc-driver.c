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
#include <string.h>
#include "kc-internal.h"
#include "kc-backend.h"

#define PROC_CRYPTO		"/proc/crypto"
#define FIELD_MAX		128	/* CRYPTO_MAX_ALG_NAME */

/* The fields of an entry of /proc/crypto that name a driver */
struct proc_entry {
	char name[FIELD_MAX];
	char driver[FIELD_MAX];
	char type[32];
};

/* Copies at most size - 1 bytes and terminates, as strlcpy() */
static void copy(char *dst, const char *src, size_t size)
{
	size_t len = strnlen(src, size - 1);

	memcpy(dst, src, len);
	dst[len] = '\0';
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

KC_EXPORT int kc_algo_available(const char *type, const char *name,
				struct kc_error *e)
{
	if (!types_taken(type))
		return kc_fail(e, KC_USAGE, EINVAL,
			       "unknown algorithm type \"%s\"", type);
	return KC_BACKEND->available(type, name, e);
}

KC_EXPORT int kc_driver_check(const char *type, const char *driver,
			      const char *algo, struct kc_error *e)
{
	const char *const *taken = types_taken(type);
	struct proc_entry pe;
	FILE *f;
	int ret, err;

	if (!taken)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "unknown algorithm type \"%s\"", type);
	f = fopen(PROC_CRYPTO, "r");
	if (!f) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "cannot read %s: %s",
			       PROC_CRYPTO, strerror(err));
	}
	while ((ret = read_entry(f, &pe)) > 0)
		if (is_taken(taken, pe.type) &&
		    strcmp(pe.driver, driver) == 0 &&
		    strcmp(pe.name, algo) == 0)
			break;
	err = errno;
	fclose(f);		/* intentionally ignored */
	if (ret < 0)
		return kc_fail(e, KC_FAILED, err, "cannot read %s: %s",
			       PROC_CRYPTO, strerror(err));
	if (ret == 0)
		return kc_fail(e, KC_REFUSED, 0,
			       "%s lists no %s driver \"%s\" of %s",
			       PROC_CRYPTO, type, driver, algo);
	return kc_ok(e);
}
