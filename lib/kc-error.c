/*
 * kc-error.c - struct kc_error and its statuses (libkcrypto)
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

#include <stdarg.h>
#include <stdio.h>
#include "kc-internal.h"

int kc_fail(struct kc_error *e, enum kc_status status, int errnum,
	    const char *fmt, ...)
{
	va_list ap;

	if (e) {
		e->status = status;
		e->errnum = errnum;
		va_start(ap, fmt);
		vsnprintf(e->msg, sizeof(e->msg), fmt, ap);	/* may cut */
		va_end(ap);
	}
	return status;
}

int kc_ok(struct kc_error *e)
{
	if (e) {
		e->status = KC_OK;
		e->errnum = 0;
		e->msg[0] = '\0';
	}
	return KC_OK;
}
