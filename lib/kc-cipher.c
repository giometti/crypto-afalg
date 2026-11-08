/*
 * kc-cipher.c - block ciphers with PKCS#7 padding (libkcrypto)
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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include "kc-internal.h"
#include "kc-backend.h"

#define CHUNK			8192	/* sent and read back at once */
#define KEYCRYPT_PREFIX		KC_KEYCRYPT_DRIVER_PREFIX

/* Through AF_ALG (tfm, op) or through keycrypt (kx), never both */
struct kc_cipher {
	struct kc_tfm *tfm;
	struct kc_op *op;
	struct kc_kcrypt *kx;
	char driver[KC_NAME_MAX + 1];
	unsigned char iv[KC_BLOCK_MAX];
	size_t key_len;			/* 0: not known here */
	bool encrypt;
	size_t block;
	unsigned char part[KC_BLOCK_MAX];	/* input short of a block */
	size_t part_len;
	unsigned char held[KC_BLOCK_MAX];	/* the last block decrypted */
	bool have_held;
	bool done;			/* finished, or its stream is lost */
	unsigned char buf[CHUNK];		/* what the kernel gives back */
};

/*
 * Whole blocks through the kernel, appended to out; in decryption the
 * last one is held back, since it carries the padding
 */
static int crypt_blocks(struct kc_cipher *c, const unsigned char *in,
			size_t len, unsigned char *out, size_t *out_len,
			struct kc_error *e)
{
	size_t got = len;
	int status;

	if (c->kx)
		status = kc_keycrypt_update(c->kx, in, c->buf, len, e);
	else {
		status = KC_BACKEND->send(c->op, in, len, e);
		if (!status)
			status = KC_BACKEND->recv(c->op, c->buf, len, &got, e);
	}
	if (status)
		return status;
	if (got != len)
		return kc_fail(e, KC_FAILED, 0,
			       "too few data received from the kernel!");

	if (c->encrypt) {
		memcpy(out + *out_len, c->buf, len);
		*out_len += len;
		return KC_OK;
	}
	if (c->have_held) {
		memcpy(out + *out_len, c->held, c->block);
		*out_len += c->block;
	}
	memcpy(out + *out_len, c->buf, len - c->block);
	*out_len += len - c->block;
	memcpy(c->held, c->buf + len - c->block, c->block);
	c->have_held = true;
	return KC_OK;
}

static int stop(struct kc_cipher *c, int status)
{
	c->done = true;
	return status;
}

/*
 * The key's own algorithm and backend: a name may only repeat the
 * algorithm, never choose a driver
 */
static int open_keycrypt(struct kc_cipher *c, const char *name,
			 const struct kc_key *k, const void *iv,
			 unsigned int min_tier, struct kc_error *e)
{
	const char *algo;
	int status;

	if (c->block != KC_KEYCRYPT_IV_LEN)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "invalid IV length %zu for a keycrypt key",
			       c->block);
	status = kc_keycrypt_open(&c->kx, k->serial, c->encrypt, iv, min_tier,
				  e);
	if (status)
		return status;
	algo = kc_keycrypt_algo(c->kx);
	if (!algo)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "the keycrypt key %d is not of a cipher this library runs",
			       k->serial);
	if (name && strcmp(name, algo) != 0)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "the keycrypt key %d is of %s, with its own backend: \"%s\" is not for it",
			       k->serial, algo, name);
	memcpy(c->iv, kc_keycrypt_iv(c->kx), KC_KEYCRYPT_IV_LEN);
	c->key_len = kc_keycrypt_key_len(c->kx);
	snprintf(c->driver, sizeof(c->driver), KEYCRYPT_PREFIX "%s",
		 kc_keycrypt_backend(c->kx));
	return kc_ok(e);
}

static int open_afalg(struct kc_cipher *c, const char *name,
		      const struct kc_key *k, const void *iv,
		      unsigned int min_tier, struct kc_error *e)
{
	int status;

	if (min_tier)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "a minimum tier is for keycrypt keys, and the key goes to AF_ALG");
	/* An errno of its own, so that a caller can ask for the name */
	if (!name)
		return kc_fail(e, KC_USAGE, EDESTADDRREQ,
			       "a cipher through AF_ALG needs its name");
	if (iv)
		memcpy(c->iv, iv, c->block);
	else if (getrandom(c->iv, c->block, 0) != (ssize_t) c->block)
		return kc_fail(e, KC_FAILED, errno,
			       "cannot get a random IV: %s", strerror(errno));

	/* A keyring key keeps its length in the kernel */
	if (k->type == KC_KEY_RAW)
		c->key_len = k->len;

	/* open() takes no name longer than KC_NAME_MAX */
	status = KC_BACKEND->open(&c->tfm, "skcipher", name, e);
	if (!status) {
		strcpy(c->driver, name);
		status = KC_BACKEND->set_key(c->tfm, k, e);
	}
	if (!status)
		status = KC_BACKEND->start(c->tfm, &c->op, e);
	if (!status)
		status = KC_BACKEND->set_op_iv(c->op, c->encrypt, c->iv,
					       c->block, e);
	return status;
}

/*
 * Whether keycrypt is asked for a keyring key, from its type, so that
 * keycrypt's command reaches no key known to be of another type: KC_OK
 * to ask it, with *typed when the key is of its type, KC_REFUSED for
 * AF_ALG. A key revoked, expired or gone fails here, as for AF_ALG. AUTO
 * gives any other key it cannot describe to AF_ALG, which answers for
 * it, with *why the cause; KEYCRYPT asks keycrypt for a key the caller
 * may not view, and refuses a key of another type.
 */
static int keycrypt_or_not(enum kc_backend_sel sel, const struct kc_key *k,
			   bool *typed, int *why, struct kc_error *e)
{
	int status, err;

	status = kc_key_is_keycrypt(k, e);
	*typed = status == KC_OK;
	if (status == KC_REFUSED && sel == KC_BACKEND_KEYCRYPT)
		return kc_fail(e, KC_USAGE, EOPNOTSUPP,
			       "the key %d is not a keycrypt key", k->serial);
	if (status != KC_FAILED)
		return status;
	err = e->errnum;
	if (err == EKEYREVOKED || err == EKEYEXPIRED || err == ENOKEY)
		return kc_fail(e, KC_FAILED, err, "key %d: %s", k->serial,
			       strerror(err));
	if (sel == KC_BACKEND_KEYCRYPT)
		return err == EACCES ? KC_OK : status;
	*why = err;
	return KC_REFUSED;
}

KC_EXPORT int kc_cipher_open_backend(struct kc_cipher **c,
				     enum kc_backend_sel sel, const char *name,
				     const struct kc_key *k, int encrypt,
				     const void *iv, size_t iv_len,
				     unsigned int min_tier, struct kc_error *e)
{
	struct kc_cipher *cipher;
	struct kc_error own;
	bool typed = false;
	size_t len;
	int status, err, why = 0;

	/* The errno of a step decides the next one */
	if (!e)
		e = &own;
	*c = NULL;
	if (!k)
		return kc_fail(e, KC_USAGE, EINVAL, "a cipher needs a key");
	if (iv_len == 0 || iv_len > KC_BLOCK_MAX)
		return kc_fail(e, KC_USAGE, EINVAL, "invalid IV length %zu",
			       iv_len);
	if (!iv && !encrypt)
		return kc_fail(e, KC_USAGE, EINVAL, "decryption needs the IV");
	if (sel != KC_BACKEND_AUTO && sel != KC_BACKEND_AFALG &&
	    sel != KC_BACKEND_KEYCRYPT)
		return kc_fail(e, KC_USAGE, EINVAL, "unknown backend %d", sel);
	if (sel == KC_BACKEND_KEYCRYPT && k->type != KC_KEY_SERIAL)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "a key in clear is not a keycrypt key");
	cipher = calloc(1, sizeof(*cipher));
	if (!cipher)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	cipher->encrypt = encrypt;
	cipher->block = iv_len;

	/*
	 * AUTO asks keycrypt only with the IV such a key takes; once asked,
	 * every answer of keycrypt is the answer, and its "not a keycrypt
	 * key" a wrong key only for one whose type could not be read
	 */
	status = KC_REFUSED;
	if (k->type == KC_KEY_SERIAL && (sel == KC_BACKEND_KEYCRYPT ||
	    (sel == KC_BACKEND_AUTO && iv_len == KC_KEYCRYPT_IV_LEN)))
		status = keycrypt_or_not(sel, k, &typed, &why, e);
	if (status == KC_OK) {
		status = open_keycrypt(cipher, name, k, iv, min_tier, e);
		err = e->errnum;
		if (status == KC_REFUSED && err == EOPNOTSUPP && !typed)
			status = kc_fail(e, KC_USAGE, err,
					 "the key %d is not a keycrypt key, or the kernel has no keycrypt",
					 k->serial);
		else if (status == KC_REFUSED)
			status = kc_fail(e, KC_FAILED, err,
					 "keycrypt, key %d: the kernel did not open it: %s",
					 k->serial, strerror(err));
	}
	if (status == KC_REFUSED) {
		status = open_afalg(cipher, name, k, iv, min_tier, e);

		/* Its failure says why the key went there */
		if (status && why) {
			len = strlen(e->msg);
			snprintf(e->msg + len, sizeof(e->msg) - len,
				 " (the type of the key could not be read: %s)",
				 strerror(why));
		}
	}
	if (status) {
		kc_cipher_free(cipher);
		return status;
	}
	*c = cipher;
	return kc_ok(e);
}

KC_EXPORT int kc_cipher_open(struct kc_cipher **c, const char *name,
			     const struct kc_key *k, int encrypt,
			     const void *iv, size_t iv_len, struct kc_error *e)
{
	return kc_cipher_open_backend(c, KC_BACKEND_AUTO, name, k, encrypt, iv,
				      iv_len, 0, e);
}

KC_EXPORT int kc_cipher_iv(const struct kc_cipher *c, void *iv, size_t len,
			   struct kc_error *e)
{
	if (len < c->block)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "%zu bytes are too few for an IV of %zu", len,
			       c->block);
	memcpy(iv, c->iv, c->block);
	return kc_ok(e);
}

KC_EXPORT const char *kc_cipher_driver(const struct kc_cipher *c)
{
	return c->driver;
}

KC_EXPORT size_t kc_cipher_key_len(const struct kc_cipher *c)
{
	return c->key_len;
}

KC_EXPORT int kc_cipher_update(struct kc_cipher *c, const void *in,
			       size_t len, void *out, size_t *out_len,
			       struct kc_error *e)
{
	const unsigned char *p = in;
	size_t n;
	int status;

	*out_len = 0;
	if (c->done)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "the cipher cannot be used any more");

	if (c->part_len > 0) {
		n = c->block - c->part_len;
		if (n > len)
			n = len;
		memcpy(c->part + c->part_len, p, n);
		c->part_len += n;
		p += n;
		len -= n;
		if (c->part_len < c->block)
			return kc_ok(e);
		status = crypt_blocks(c, c->part, c->block, out, out_len, e);
		if (status)
			return stop(c, status);
		c->part_len = 0;
	}

	while (len >= c->block) {
		n = len - len % c->block;
		if (n > CHUNK)
			n = CHUNK - CHUNK % c->block;
		status = crypt_blocks(c, p, n, out, out_len, e);
		if (status)
			return stop(c, status);
		p += n;
		len -= n;
	}

	memcpy(c->part, p, len);
	c->part_len = len;
	return kc_ok(e);
}

KC_EXPORT int kc_cipher_final(struct kc_cipher *c, void *out,
			      size_t *out_len, struct kc_error *e)
{
	unsigned char diff;
	size_t pad, i;
	int status;

	*out_len = 0;
	if (c->done)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "the cipher cannot be used any more");
	c->done = true;
	if (c->encrypt) {
		/* PKCS#7: n bytes all n, a whole block when nothing is left */
		pad = c->block - c->part_len;
		memset(c->part + c->part_len, pad, pad);
		status = crypt_blocks(c, c->part, c->block, out, out_len, e);
		c->part_len = 0;
		if (!status && c->kx)
			status = kc_keycrypt_final(c->kx, e);
		return status ? status : kc_ok(e);
	}

	/* Every block went through: the kernel's context can end */
	if (c->kx) {
		status = kc_keycrypt_final(c->kx, e);
		if (status)
			return status;
	}

	/* As openssl, every whole block goes out before the refusal */
	if (c->part_len > 0 || !c->have_held) {
		if (c->have_held) {
			memcpy(out, c->held, c->block);
			*out_len = c->block;
			c->have_held = false;
		}
		return kc_fail(e, KC_REFUSED, 0,
			       "bad decrypt (wrong final block length)");
	}

	/* PKCS#7, with no exit at the first wrong byte: no timing to read */
	pad = c->held[c->block - 1];
	diff = pad < 1 || pad > c->block;
	for (i = c->block - (diff ? 0 : pad); i < c->block; i++)
		diff |= c->held[i] ^ pad;
	if (diff)
		return kc_fail(e, KC_REFUSED, 0, "bad decrypt (wrong padding)");
	memcpy(out, c->held, c->block - pad);
	*out_len = c->block - pad;
	c->have_held = false;
	return kc_ok(e);
}

KC_EXPORT void kc_cipher_free(struct kc_cipher *c)
{
	if (!c)
		return;
	if (c->op)
		KC_BACKEND->end(c->op);
	if (c->tfm)
		KC_BACKEND->close(c->tfm);
	kc_keycrypt_close(c->kx);
	explicit_bzero(c, sizeof(*c));
	free(c);
}
