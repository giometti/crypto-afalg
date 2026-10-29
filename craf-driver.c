/*
 * craf-driver.c - craf cipher drivers: what craf says of them
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

#include <string.h>
#include "craf.h"

#define PROC_CRYPTO		"/proc/crypto"

/*
 * A name the kernel refused to bind is "not available", in craf's words;
 * any other failure is told as the library tells it
 */
static int driver_err(const char *what, const char *name,
		      const struct kc_error *e)
{
	if (e->status == KC_REFUSED && e->errnum)
		return craf_err(CRAF_FAILED, "%s \"%s\" not available: %s",
				what, name, strerror(e->errnum));
	return craf_err(CRAF_FAILED, "%s", e->msg);
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
	char found[CRAF_STR_MAX + 1];
	struct kc_error e;
	int status;

	status = kc_driver_algo("skcipher", driver, found, sizeof(found), &e);
	if (status == KC_REFUSED) {
		if (user)
			status = kc_algo_listed("skcipher", driver, &e);
		if (status == KC_OK)
			return craf_err(mismatch,
					"%s \"%s\" names an algorithm, not a driver",
					what, driver);
		if (status == KC_REFUSED)
			return craf_err(CRAF_FAILED,
					"%s \"%s\" is not listed in %s", what,
					driver, PROC_CRYPTO);
	}
	if (status)
		return craf_err(CRAF_FAILED, "%s", e.msg);
	if (strcmp(found, algo) != 0)
		return craf_err(mismatch, "%s \"%s\" is a driver of %s, not %s",
				what, driver, found, algo);
	return CRAF_OK;
}

/*
 * A driver of <algo> named on the command line: it is bound first, since
 * one the kernel builds from a template is listed only once used
 */
int craf_driver_check(const char *what, const char *driver, const char *algo,
		      int mismatch)
{
	struct kc_error e;

	if (kc_algo_available("skcipher", driver, &e))
		return driver_err(what, driver, &e);
	return craf_driver_listed(what, driver, algo, mismatch, true);
}

/* The driver the kernel takes for <algo>, into <driver> */
int craf_driver_for_algo(const char *algo, char *driver)
{
	struct kc_error e;

	if (kc_driver_for_algo("skcipher", algo, driver, CRAF_STR_MAX + 1, &e))
		return driver_err("cipher_algo", algo, &e);
	return CRAF_OK;
}

/*
 * A name given where the name of an algorithm is expected, as of
 * -cipher-algo: a driver is told, with the algorithm it is a driver of
 * and <driver_opt>, the option that takes it, when there is one; a name
 * listed as neither is left to the kernel to refuse
 */
int craf_check_algo_name(const char *cmd, const char *type, const char *opt,
			 const char *name, const char *driver_opt)
{
	char algo[CRAF_STR_MAX + 1];
	struct kc_error e;
	int status;

	status = kc_algo_listed(type, name, &e);
	if (status == KC_OK)
		return CRAF_OK;
	if (status == KC_REFUSED) {
		status = kc_driver_algo(type, name, algo, sizeof(algo), &e);
		if (status == KC_OK && driver_opt)
			return craf_err(CRAF_USAGE,
					"%s \"%s\" is a driver of %s: give it with %s",
					opt, name, algo, driver_opt);
		if (status == KC_OK)
			return craf_err(CRAF_USAGE,
					"%s \"%s\" is a driver of %s, give the name of the algorithm",
					opt, name, algo);
		if (status == KC_REFUSED)
			return CRAF_OK;
	}
	return craf_err(CRAF_FAILED, "%s: %s", cmd, e.msg);
}
