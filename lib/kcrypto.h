/*
 * kcrypto.h - the cryptography of the Linux kernel for user space
 *	       (libkcrypto)
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

#ifndef KCRYPTO_H
#define KCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define KC_MSG_MAX		1024

/*
 * Every function that can fail returns one of these and, when its last
 * argument is not NULL, fills it in: the library never prints and never
 * exits
 */
enum kc_status {
	KC_OK = 0,
	KC_REFUSED = 1,		/* the data or the answer is "no" */
	KC_USAGE = 2,		/* an argument is wrong */
	KC_FAILED = 3,		/* it could not be done */
};

/*
 * The caller allocates struct kc_error: a change of its size, KC_MSG_MAX
 * included, changes the ABI and so the soname, even before version 1.0
 */
struct kc_error {
	enum kc_status status;
	int errnum;		/* the errno of the cause, or 0 */
	char msg[KC_MSG_MAX];
};

/*
 * Whether the kernel has an algorithm or a driver of the given type
 * ("skcipher" or "hash"), asked to the kernel itself: KC_REFUSED is its
 * "no", KC_FAILED that the question got no answer
 */
extern int kc_algo_available(const char *type, const char *name,
			     struct kc_error *e);

/*
 * Whether /proc/crypto lists driver as a driver of algo that a socket of
 * the given type takes: KC_REFUSED when it does not, KC_FAILED only when
 * /proc/crypto cannot be read. It does not ask the kernel, so a driver
 * the kernel builds from a template is listed only once something has
 * used it since the boot; kc_algo_available() on its name builds it.
 */
extern int kc_driver_check(const char *type, const char *driver,
			   const char *algo, struct kc_error *e);

#endif /* KCRYPTO_H */
