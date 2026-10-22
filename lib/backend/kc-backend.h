/*
 * kc-backend.h - the interface between libkcrypto and its backends
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

#ifndef KC_BACKEND_H
#define KC_BACKEND_H

#include "kc-internal.h"

/*
 * What a backend does for the library; every function returns a
 * kc_status and fills e as the library's own functions do
 */
struct kc_backend {
	/* Whether the kernel takes name as an algorithm of type */
	int (*available)(const char *type, const char *name,
			 struct kc_error *e);
};

/* The AF_ALG backend, the only one: no choice of backend is exposed */
extern const struct kc_backend kc_afalg_backend;
#define KC_BACKEND		(&kc_afalg_backend)

#endif /* KC_BACKEND_H */
