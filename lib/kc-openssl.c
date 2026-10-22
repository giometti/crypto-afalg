/*
 * kc-openssl.c - the format of openssl enc with a passphrase (libkcrypto)
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
#include "kc-internal.h"

#define MAGIC			"Salted__"
#define MAGIC_LEN		(KC_OPENSSL_HEADER_LEN - KC_OPENSSL_SALT_LEN)

KC_EXPORT int kc_openssl_header(const void *buf, size_t len,
				uint8_t salt[KC_OPENSSL_SALT_LEN],
				struct kc_error *e)
{
	if (len < KC_OPENSSL_HEADER_LEN)
		return kc_fail(e, KC_REFUSED, 0,
			       "truncated openssl enc header (%zu bytes)", len);
	if (memcmp(buf, MAGIC, MAGIC_LEN) != 0)
		return kc_fail(e, KC_REFUSED, 0, "no \"%s\" header", MAGIC);
	memcpy(salt, (const uint8_t *) buf + MAGIC_LEN, KC_OPENSSL_SALT_LEN);
	return kc_ok(e);
}

KC_EXPORT void kc_openssl_header_make(uint8_t buf[KC_OPENSSL_HEADER_LEN],
				      const uint8_t salt[KC_OPENSSL_SALT_LEN])
{
	memcpy(buf, MAGIC, MAGIC_LEN);
	memcpy(buf + MAGIC_LEN, salt, KC_OPENSSL_SALT_LEN);
}
