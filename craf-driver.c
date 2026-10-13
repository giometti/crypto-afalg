/*
 * craf-driver.c - craf cipher drivers, chosen as the kernel does
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

#include <stdlib.h>
#include <string.h>
#include "craf.h"

#define PROC_CRYPTO		"/proc/crypto"

/* The fields of an entry of /proc/crypto that choose a driver */
struct proc_entry {
	char name[CRAF_STR_MAX + 1];
	char driver[CRAF_STR_MAX + 1];
	char type[32];
	char selftest[16];
	char internal[16];
	long priority;
};

/* Copies at most size - 1 bytes and terminates, as strlcpy() */
static void copy(char *dst, const char *src, size_t size)
{
	size_t len = strnlen(src, size - 1);

	memcpy(dst, src, len);
	dst[len] = '\0';
}

/* The next entry: 1, or 0 at the end of the file, -1 on a read error */
static int read_entry(FILE *f, struct proc_entry *e)
{
	char line[512], *sep, *val;
	bool any = false;
	size_t len;

	memset(e, 0, sizeof(*e));
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
			copy(e->name, val, sizeof(e->name));
		else if (strcmp(line, "driver") == 0)
			copy(e->driver, val, sizeof(e->driver));
		else if (strcmp(line, "type") == 0)
			copy(e->type, val, sizeof(e->type));
		else if (strcmp(line, "selftest") == 0)
			copy(e->selftest, val, sizeof(e->selftest));
		else if (strcmp(line, "internal") == 0)
			copy(e->internal, val, sizeof(e->internal));
		else if (strcmp(line, "priority") == 0)
			e->priority = strtol(val, NULL, 10);
	}
	if (ferror(f))
		return -1;
	return any;
}

/*
 * The kernel gives an AF_ALG skcipher socket an lskcipher too: the
 * type mask of crypto_skcipher_type does not tell them apart
 */
static bool is_skcipher(const struct proc_entry *e)
{
	return strcmp(e->type, "skcipher") == 0 ||
	       strcmp(e->type, "lskcipher") == 0;
}

/* What crypto_alg_mod_lookup() takes: tested, and not internal */
static bool usable(const struct proc_entry *e)
{
	return is_skcipher(e) && strcmp(e->selftest, "passed") == 0 &&
	       strcmp(e->internal, "no") == 0;
}

/* A bind by name that leaves nothing open: the name is usable */
static int bind_check(const char *what, const char *name)
{
	int s;

	s = afalg_socket();
	if (s < 0)
		return craf_err(CRAF_FAILED, "socket(AF_ALG): %m");
	if (afalg_bind(s, "skcipher", name) < 0) {
		err("%s \"%s\" not available: %m", what, name);
		close(s);
		return CRAF_FAILED;
	}
	close(s);
	return CRAF_OK;
}

/*
 * A driver already listed as one of <algo>, read without binding it, so
 * that a name from an archive makes the kernel build nothing; <what>
 * names where the driver comes from, and <mismatch> is the exit status
 * for a driver listed for another algorithm. The name of an algorithm is
 * a mismatch too when the user gave it; from an archive it is a driver
 * that is not listed.
 */
int craf_driver_listed(const char *what, const char *driver,
		       const char *algo, int mismatch, bool user)
{
	struct proc_entry e;
	bool is_algo = false;
	FILE *f;
	int ret;

	f = fopen(PROC_CRYPTO, "r");
	if (!f)
		return craf_err(CRAF_FAILED, "cannot read %s: %m", PROC_CRYPTO);
	while ((ret = read_entry(f, &e)) > 0) {
		if (!is_skcipher(&e))
			continue;
		if (strcmp(e.driver, driver) == 0)
			break;
		if (strcmp(e.name, driver) == 0)
			is_algo = true;
	}
	fclose(f);
	if (ret < 0)
		return craf_err(CRAF_FAILED, "cannot read %s: %m", PROC_CRYPTO);
	if (ret == 0 && is_algo && user)
		return craf_err(mismatch,
				"%s \"%s\" names an algorithm, not a driver",
				what, driver);
	if (ret == 0)
		return craf_err(CRAF_FAILED, "%s \"%s\" is not listed in %s",
				what, driver, PROC_CRYPTO);
	if (strcmp(e.name, algo) != 0)
		return craf_err(mismatch, "%s \"%s\" is a driver of %s, not %s",
				what, driver, e.name, algo);
	return CRAF_OK;
}

/*
 * A driver of <algo> named on the command line: it is bound first, since
 * one the kernel builds from a template is listed only once used
 */
int craf_driver_check(const char *what, const char *driver, const char *algo,
		      int mismatch)
{
	int status;

	status = bind_check(what, driver);
	if (status)
		return status;
	return craf_driver_listed(what, driver, algo, mismatch, true);
}

/*
 * The driver the kernel takes for an algorithm (crypto/api.c,
 * __crypto_alg_lookup()): the highest priority, the first one listed
 * among equals. A bind by the algorithm's name comes first, so that the
 * kernel instantiates the templates it needs and lists them.
 */
int craf_driver_for_algo(const char *algo, char *driver)
{
	struct proc_entry e;
	long best = 0;
	bool found = false;
	FILE *f;
	int ret, status;

	status = bind_check("cipher_algo", algo);
	if (status)
		return status;
	f = fopen(PROC_CRYPTO, "r");
	if (!f)
		return craf_err(CRAF_FAILED, "cannot read %s: %m", PROC_CRYPTO);
	while ((ret = read_entry(f, &e)) > 0) {
		if (!usable(&e) || strcmp(e.name, algo) != 0)
			continue;
		if (found && e.priority <= best)
			continue;
		strcpy(driver, e.driver);
		best = e.priority;
		found = true;
	}
	fclose(f);
	if (ret < 0)
		return craf_err(CRAF_FAILED, "cannot read %s: %m", PROC_CRYPTO);
	if (!found)
		return craf_err(CRAF_FAILED, "no driver of %s is listed in %s",
				algo, PROC_CRYPTO);
	return CRAF_OK;
}
