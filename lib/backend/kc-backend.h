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

#include <stdbool.h>
#include "kc-internal.h"

/* A key as a backend sets it: raw bytes, or a keyring key by serial */
struct kc_key {
	enum {
		KC_KEY_RAW,
		KC_KEY_SERIAL,
	} type;
	int32_t serial;		/* a key_serial_t of keyutils.h */
	bool loaded;		/* by the library, which unloads it */
	size_t len;
	unsigned char data[];
};

/* An algorithm with its key, and one operation on it, as a backend has them */
struct kc_tfm;
struct kc_op;

/*
 * What a backend does for the library; every function returns a
 * kc_status and fills e as the library's own functions do
 */
struct kc_backend {
	/* Whether set_key() takes a keyring key */
	bool key_serial;

	/* Whether the kernel takes name as an algorithm of type */
	int (*available)(const char *type, const char *name,
			 struct kc_error *e);

	/* An algorithm or a driver of type, by name */
	int (*open)(struct kc_tfm **t, const char *type, const char *name,
		    struct kc_error *e);
	int (*set_key)(struct kc_tfm *t, const struct kc_key *k,
		       struct kc_error *e);
	void (*close)(struct kc_tfm *t);

	/* One operation: data in, all of it, then the result out */
	int (*start)(struct kc_tfm *t, struct kc_op **op, struct kc_error *e);
	/* Of a cipher only, before the data */
	int (*set_op_iv)(struct kc_op *op, int encrypt, const void *iv,
			 size_t iv_len, struct kc_error *e);
	int (*send)(struct kc_op *op, const void *buf, size_t len,
		    struct kc_error *e);
	int (*recv)(struct kc_op *op, void *buf, size_t len, size_t *got,
		    struct kc_error *e);
	void (*end)(struct kc_op *op);
};

/* The AF_ALG backend, for every algorithm by name */
extern const struct kc_backend kc_afalg_backend;
#define KC_BACKEND		(&kc_afalg_backend)

/*
 * The keycrypt backend, for a cipher whose key is a keycrypt key: the
 * algorithm and the backend that runs it are the key's own. An operation
 * context, opened on the key by its serial, encrypting with the IV the
 * kernel draws when iv is NULL; kc_keycrypt_open() gives KC_REFUSED, with
 * EOPNOTSUPP, exactly when the key is not a keycrypt key (or the kernel
 * has no keycrypt), and with ENOSYS where a filter refuses the command.
 */
#define KC_KEYCRYPT_BACKEND_MAX	16	/* characters of a backend's name */

struct kc_kcrypt;

extern int kc_keycrypt_open(struct kc_kcrypt **x, int32_t serial,
			    int encrypt, const void *iv, unsigned int min_tier,
			    struct kc_error *e);
extern const char *kc_keycrypt_algo(const struct kc_kcrypt *x);
extern const unsigned char *kc_keycrypt_iv(const struct kc_kcrypt *x);
extern const char *kc_keycrypt_backend(const struct kc_kcrypt *x);
/* Whole blocks, any number of them */
extern int kc_keycrypt_update(struct kc_kcrypt *x, const void *in, void *out,
			      size_t len, struct kc_error *e);
extern int kc_keycrypt_final(struct kc_kcrypt *x, struct kc_error *e);
extern void kc_keycrypt_close(struct kc_kcrypt *x);

#endif /* KC_BACKEND_H */
