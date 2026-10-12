/*
 * afalg.h - AF_ALG socket layer for Linux (libafalg)
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

#ifndef AFALG_H
#define AFALG_H

#include <stdint.h>
#include <sys/types.h>
#include <linux/if_alg.h>

#define AFALG_MAX_IV_LEN	32

/* A key carries its own type: raw bytes, or a keyring key by serial */
struct afalg_key {
	enum {
		AFALG_KEY_RAW,
		AFALG_KEY_SERIAL,
	} type;
	union {
		struct {
			const char *data;
			size_t len;
		} raw;
		int32_t serial;		/* a key_serial_t of keyutils.h */
	};
};

/*
 * Every function returns -1 on failure, with the cause in errno: the
 * error of the system call it wraps, or one of the library's own:
 * ENAMETOOLONG from afalg_bind() for a type or a name that does not fit
 * struct sockaddr_alg, EINVAL from afalg_set_op_iv() for an IV longer
 * than AFALG_MAX_IV_LEN, EOPNOTSUPP from afalg_set_key() for a keyring
 * key when built without ALG_SET_KEY_BY_KEY_SERIAL and EINVAL for an
 * unknown key type.
 */
extern int afalg_socket(void);
extern int afalg_bind(int s, const char *type, const char *name);
extern int afalg_set_key(int s, const struct afalg_key *key);
extern int afalg_accept(int s);

/*
 * For a skcipher: iv_len must be the IV size of the cipher, which the
 * kernel refuses otherwise. Returns 0 on success.
 */
extern int afalg_set_op_iv(int fd, int op, const void *iv, size_t iv_len);

/*
 * Always with MSG_MORE: the data continue one operation, so the cipher
 * chains its IV and the digest covers every call up to afalg_recv()
 */
extern ssize_t afalg_send(int fd, const void *buf, size_t len);
extern ssize_t afalg_recv(int fd, void *buf, size_t len);

#endif /* AFALG_H */
