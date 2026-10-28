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
#define KC_NAME_MAX		63	/* of an algorithm or a driver */
#define KC_HASH_MAX		64	/* the longest digest, SHA-512's */
#define KC_BLOCK_MAX		32	/* the longest IV the library takes */
#define KC_OPENSSL_SALT_LEN	8
#define KC_OPENSSL_HEADER_LEN	16	/* "Salted__" and the salt */
#define KC_OPENSSL_KEY_MAX	64	/* no key of openssl enc is longer */

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
 * What /proc/crypto lists, among the types a socket of the given type
 * takes: KC_REFUSED when it does not list it, KC_FAILED only when
 * /proc/crypto cannot be read. These do not ask the kernel, so a driver
 * the kernel builds from a template is listed only once something has
 * used it since the boot; kc_algo_available() on its name builds it.
 *
 * kc_driver_check(): whether driver is a driver of algo;
 * kc_driver_algo(): the algorithm of driver, into algo of size bytes;
 * kc_algo_listed(): whether algo is the name of an algorithm.
 */
extern int kc_driver_check(const char *type, const char *driver,
			   const char *algo, struct kc_error *e);
extern int kc_driver_algo(const char *type, const char *driver, char *algo,
			  size_t size, struct kc_error *e);
extern int kc_algo_listed(const char *type, const char *algo,
			  struct kc_error *e);

/*
 * The driver the kernel takes for algo, into driver of size bytes, chosen
 * as crypto/api.c does: the highest priority among the tested, not
 * internal drivers /proc/crypto lists, the first one among equals. The
 * kernel is asked first, as by kc_algo_available(), so that it lists what
 * it builds from a template: KC_REFUSED when it has no such algorithm, or
 * when /proc/crypto lists no driver it would take; KC_FAILED when the
 * kernel or /proc/crypto could not be asked; KC_USAGE (ENAMETOOLONG) when
 * the driver does not fit.
 */
extern int kc_driver_for_algo(const char *type, const char *algo,
			      char *driver, size_t size, struct kc_error *e);

/*
 * The sizes of an skcipher, by the name of an algorithm or of a driver:
 * its block, its IV and its shortest and longest key, in bytes, as
 * /proc/crypto lists them. The kernel is asked first, as by
 * kc_algo_available(), so that it lists what it builds from a template:
 * KC_REFUSED when it has no such cipher, or /proc/crypto does not list it;
 * KC_FAILED when the kernel or /proc/crypto could not be asked, or it
 * lists the cipher without the four sizes; KC_USAGE (ENAMETOOLONG) for a
 * name longer than KC_NAME_MAX. The sizes alone do not tell modes apart:
 * xts(aes) and cts(cbc(aes)) have the block and the IV of cbc(aes).
 */
extern int kc_cipher_sizes(const char *name, size_t *block, size_t *iv_len,
			   size_t *key_min, size_t *key_max,
			   struct kc_error *e);

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
 * is, not looked up. A description that the kernel's search finds in more
 * than one key of the keyrings the caller can read is KC_USAGE
 * (ENOTUNIQ): where the kernel compares descriptions as strings, the
 * library does the same; where it does not (an asymmetric key by "id:"),
 * the library asks the kernel, and a key it cannot ask about, as one it
 * may not link, makes the answer unknown. That, and a key of the keyrings
 * that cannot be described, is KC_FAILED with its errno, never a pass.
 * What is opened with a keyring key is KC_FAILED where
 * kc_key_serial_supported() is 0 (EOPNOTSUPP) or the kernel is older than
 * Linux 6.2 (its errno).
 */
extern int kc_key_spec(struct kc_key **k, const char *spec,
		       struct kc_error *e);

/*
 * Whether this library can hand the kernel a keyring key: 1 when it was
 * built with an <linux/if_alg.h> that defines ALG_SET_KEY_BY_KEY_SERIAL,
 * 0 otherwise. The kernel takes one from Linux 6.2.
 */
extern int kc_key_serial_supported(void);

/*
 * The key of a trusted key blob, the bytes the kernel gives (keyctl pipe
 * writes them in hex), which only the trust source that sealed it can
 * load: loaded into the keyring of the calling thread, out of reach of
 * any other process and gone with that thread, and so with the process,
 * and used by its serial, as a keyring key. Use it, and free it, in that
 * thread.
 * kc_key_unload() takes it out of the keyring at once, KC_FAILED when
 * the kernel refuses (KC_OK for a key the library did not load);
 * kc_key_free() takes it out too, if it is still there, saying nothing of
 * a failure.
 */
extern int kc_key_blob(struct kc_key **k, const void *blob, size_t len,
		       struct kc_error *e);
extern int kc_key_unload(struct kc_key *k, struct kc_error *e);

/*
 * An X.509 certificate, DER, as an asymmetric keyring key for
 * kc_pkey_*(), loaded and unloaded as by kc_key_blob(): KC_FAILED, with
 * the kernel's errno, when the kernel refuses it, as it does what is not
 * a certificate, a key of an algorithm it lacks, and a self-signed one
 * whose signature does not hold. It checks the signature of no other
 * certificate: trusting the key is the caller's.
 */
extern int kc_key_cert(struct kc_key **k, const void *der, size_t len,
		       struct kc_error *e);

/*
 * A public key, a DER SubjectPublicKeyInfo as openssl pkey -pubout
 * -outform DER writes it, as an asymmetric keyring key, which the kernel
 * takes only as a certificate: wrapped in one that is not self-signed,
 * whose signature is none and which is valid from 1970 to 9999, then
 * loaded as by kc_key_cert(). The certificate names an RSA signature, so
 * the key is taken for RSA only. KC_USAGE when spki is not one DER
 * SEQUENCE len bytes long, its length in DER's shortest form, in at most
 * two bytes (EINVAL), or is longer than 16384 bytes (E2BIG).
 */
extern int kc_key_pubkey(struct kc_key **k, const void *spki, size_t len,
			 struct kc_error *e);

/* The serial of a keyring key, 0 for raw bytes */
extern int32_t kc_key_serial(const struct kc_key *k);

/*
 * Clears raw bytes and frees; a key of kc_key_blob(), kc_key_cert() or
 * kc_key_pubkey() still loaded is taken out of the keyring first, in the
 * thread that loaded it only, saying nothing of a failure. NULL is
 * ignored.
 */
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
 * length or the padding is wrong ("bad decrypt"): with a wrong length it
 * still writes the last whole block, as openssl does, and out_len says so;
 * in decryption out_len is 0 on any other failure. What was written, by
 * the refusing call too, is then to be discarded. kc_cipher_final(), and a
 * call that fails, end the cipher: after them, only kc_cipher_free().
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
 * An asymmetric keyring key, by its serial, with the parameters of keyctl
 * (as "enc=pkcs1 hash=sha256"), which the kernel reads: it never gives
 * the key out. kc_pkey_query() says what the key can do with them, the
 * sizes in bytes, the key's in bits; KC_FAILED when the kernel refuses
 * the key or the parameters, as an unknown enc= or hash=, or a key that
 * is not asymmetric; KC_USAGE (EINVAL) for a key that is not a keyring
 * key, for params or info NULL.
 * kc_pkey_verify() checks a signature of a digest: it queries the key
 * with the same parameters first, so that a refusal of them is KC_FAILED,
 * not taken for a forged signature, as are a key that cannot verify
 * (EOPNOTSUPP) and the failures of the query. A digest of 0 bytes or
 * longer than the key takes is KC_USAGE (EINVAL), and so is a signature
 * of 0 bytes; a longer signature than the key's is KC_REFUSED, and so is
 * what the kernel refuses with EKEYREJECTED, EBADMSG or EINVAL, which it
 * gives for a signature that does not hold. Its answer is only as good as
 * the digest: computed with the hash that hash= names, of the data that
 * were signed, which the kernel cannot check.
 */
#define KC_PKEY_ENCRYPT		0x01
#define KC_PKEY_DECRYPT		0x02
#define KC_PKEY_SIGN		0x04
#define KC_PKEY_VERIFY		0x08

/*
 * The caller allocates it: a change of its size or of its layout, or of
 * the values of KC_PKEY_*, which are the kernel's KEYCTL_SUPPORTS_*,
 * changes the ABI and so the soname, even before version 1.0. The library
 * sets the reserved fields to 0; a later version may answer more there.
 */
struct kc_pkey_info {
	unsigned int ops;	/* KC_PKEY_* */
	unsigned int key_size;
	size_t max_data;
	size_t max_sig;
	size_t max_enc;
	size_t max_dec;
	size_t reserved[8];
};

extern int kc_pkey_query(const struct kc_key *k, const char *params,
			 struct kc_pkey_info *info, struct kc_error *e);
extern int kc_pkey_verify(const struct kc_key *k, const char *params,
			  const void *digest, size_t digest_len,
			  const void *sig, size_t sig_len, struct kc_error *e);

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

/*
 * The key and the IV openssl enc -pbkdf2 derives from a passphrase and the
 * salt of its header: PBKDF2 over hmac (as "hmac(sha256)", its default)
 * with iter iterations, key_len bytes of key first, then iv_len of IV.
 * key_len is 1 to KC_OPENSSL_KEY_MAX, iv_len at most KC_BLOCK_MAX, and 0
 * for a mode without an IV, iter at least 1, else KC_USAGE (EINVAL);
 * KC_REFUSED when the kernel has no such HMAC. The bytes it derives are
 * cleared once the key is made; *k is NULL after a failure.
 */
extern int kc_openssl_derive(const char *hmac, const void *pass,
			     size_t pass_len,
			     const uint8_t salt[KC_OPENSSL_SALT_LEN],
			     unsigned int iter, size_t key_len,
			     struct kc_key **k, void *iv, size_t iv_len,
			     struct kc_error *e);

#endif /* KCRYPTO_H */
