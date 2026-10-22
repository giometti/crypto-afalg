/*
 * kc-internal.h - what the files of libkcrypto share, and its users do not
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

#ifndef KC_INTERNAL_H
#define KC_INTERNAL_H

#include "kcrypto.h"

/* The library is built with -fvisibility=hidden: this is its interface */
#define KC_EXPORT		__attribute__((visibility("default")))

/* Fills e, when not NULL, and returns status */
extern int kc_fail(struct kc_error *e, enum kc_status status, int errnum,
		   const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));
extern int kc_ok(struct kc_error *e);

#endif /* KC_INTERNAL_H */
