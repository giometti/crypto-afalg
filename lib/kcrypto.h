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
#define KC_HASH_MAX		64	/* the longest digest, SHA-512's */

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

/* A key: raw bytes, or a keyring key the kernel uses by its serial */
struct kc_key;

/* Raw bytes, copied; an empty key is a key too, as for HMAC */
extern int kc_key_raw(struct kc_key **k, const void *data, size_t len,
		      struct kc_error *e);

/*
 * A keyring key from "<serial>" or "[<keyring>,]<type>,<description>",
 * the keyring being @u (also "user", the default) or @s (also
 * "session"). With two commas the first field is the keyring, so a
 * description with a comma needs the keyring. A serial is taken as it
 * is, not looked up; a description is refused when more than one key
 * holds it in the keyrings the caller can read. The kernel takes a
 * keyring key from Linux 6.2, and the library only when built with an
 * <linux/if_alg.h> that defines ALG_SET_KEY_BY_KEY_SERIAL: otherwise
 * what is opened with it is KC_FAILED (EOPNOTSUPP from such a library,
 * the kernel's errno from an older kernel).
 */
extern int kc_key_spec(struct kc_key **k, const char *spec,
		       struct kc_error *e);

/* The serial of a keyring key, 0 for raw bytes */
extern int32_t kc_key_serial(const struct kc_key *k);

/* Clears raw bytes and frees; NULL is ignored */
extern void kc_key_free(struct kc_key *k);

/*
 * A hash or an HMAC, by the name of an algorithm or of a driver,
 * KC_REFUSED when the kernel has none; k is NULL for an algorithm without
 * a key, and can be freed once the hash is open. The data go in with any
 * number of kc_hash_update(), then kc_hash_final() gives the digest:
 * md_len is the room in md on the way in, KC_HASH_MAX always enough, and
 * the length of the digest on the way out. kc_hash_final(), and a call
 * that fails, end the hash: after them, only kc_hash_free().
 */
struct kc_hash;

extern int kc_hash_open(struct kc_hash **h, const char *name,
			const struct kc_key *k, struct kc_error *e);
extern int kc_hash_update(struct kc_hash *h, const void *in, size_t len,
			  struct kc_error *e);
extern int kc_hash_final(struct kc_hash *h, void *md, size_t *md_len,
			 struct kc_error *e);

/* NULL is ignored */
extern void kc_hash_free(struct kc_hash *h);

#endif /* KCRYPTO_H */
