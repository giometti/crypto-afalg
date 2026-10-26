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
#define KC_BLOCK_MAX		32	/* the longest IV the library takes */
#define KC_OPENSSL_SALT_LEN	8
#define KC_OPENSSL_HEADER_LEN	16	/* "Salted__" and the salt */

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
 * holds it in the keyrings the caller can read. What is opened with a
 * keyring key is KC_FAILED where kc_key_serial_supported() is 0
 * (EOPNOTSUPP) or the kernel is older than Linux 6.2 (its errno).
 */
extern int kc_key_spec(struct kc_key **k, const char *spec,
		       struct kc_error *e);

/*
 * Whether this library can hand the kernel a keyring key: 1 when it was
 * built with an <linux/if_alg.h> that defines ALG_SET_KEY_BY_KEY_SERIAL,
 * 0 otherwise. The kernel takes one from Linux 6.2.
 */
extern int kc_key_serial_supported(void);

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

/*
 * PBKDF2 (RFC 8018) over the HMAC hmac names, as "hmac(sha256)" or a
 * driver of one, KC_REFUSED when the kernel has none: out_len bytes into
 * out, iter and out_len at least 1
 */
extern int kc_pbkdf2(const char *hmac, const void *pass, size_t pass_len,
		     const void *salt, size_t salt_len, unsigned int iter,
		     void *out, size_t out_len, struct kc_error *e);

/*
 * A block cipher in a mode whose IV is one block, such as CBC, with the
 * PKCS#7 padding, by the name of an algorithm or of a driver, KC_REFUSED
 * when the kernel has none; iv_len is the block size too, at most
 * KC_BLOCK_MAX, and k can be freed once the cipher is open.
 * kc_cipher_update() takes any length and writes whole blocks into out,
 * which needs room for len + iv_len bytes and must not overlap in; in
 * decryption it holds the last block back. kc_cipher_final() writes the
 * rest, at most iv_len bytes: in encryption the padded last block, in
 * decryption the last block without its padding, or KC_REFUSED when the
 * length or the padding is wrong ("bad decrypt"); what was already written
 * is then to be discarded. kc_cipher_final(), and a call that fails, end
 * the cipher: after them, only kc_cipher_free().
 */
struct kc_cipher;

extern int kc_cipher_open(struct kc_cipher **c, const char *name,
			  const struct kc_key *k, int encrypt, const void *iv,
			  size_t iv_len, struct kc_error *e);
extern int kc_cipher_update(struct kc_cipher *c, const void *in, size_t len,
			    void *out, size_t *out_len, struct kc_error *e);
extern int kc_cipher_final(struct kc_cipher *c, void *out, size_t *out_len,
			   struct kc_error *e);

/* Clears and frees; NULL is ignored */
extern void kc_cipher_free(struct kc_cipher *c);

/*
 * The header openssl enc writes before what it encrypts with a passphrase
 * and a random salt: "Salted__" and the salt. kc_openssl_header() reads
 * the salt from the first KC_OPENSSL_HEADER_LEN bytes of the stream,
 * KC_REFUSED when they do not start with "Salted__" or when len, what
 * the stream had, is shorter; kc_openssl_header_make() writes one.
 */
extern int kc_openssl_header(const void *buf, size_t len,
			     uint8_t salt[KC_OPENSSL_SALT_LEN],
			     struct kc_error *e);
extern void kc_openssl_header_make(uint8_t buf[KC_OPENSSL_HEADER_LEN],
				   const uint8_t salt[KC_OPENSSL_SALT_LEN]);

#endif /* KCRYPTO_H */
