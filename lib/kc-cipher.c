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
#include <stdlib.h>
#include <string.h>
#include "kc-internal.h"
#include "kc-backend.h"

#define CHUNK			8192	/* sent and read back at once */

struct kc_cipher {
	struct kc_tfm *tfm;
	struct kc_op *op;
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
	size_t got;
	int status;

	status = KC_BACKEND->send(c->op, in, len, e);
	if (!status)
		status = KC_BACKEND->recv(c->op, c->buf, len, &got, e);
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

KC_EXPORT int kc_cipher_open(struct kc_cipher **c, const char *name,
			     const struct kc_key *k, int encrypt,
			     const void *iv, size_t iv_len, struct kc_error *e)
{
	struct kc_cipher *cipher;
	int status;

	*c = NULL;
	if (!k)
		return kc_fail(e, KC_USAGE, EINVAL, "a cipher needs a key");
	if (iv_len == 0 || iv_len > KC_BLOCK_MAX)
		return kc_fail(e, KC_USAGE, EINVAL, "invalid IV length %zu",
			       iv_len);
	cipher = calloc(1, sizeof(*cipher));
	if (!cipher)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	cipher->encrypt = encrypt;
	cipher->block = iv_len;

	status = KC_BACKEND->open(&cipher->tfm, "skcipher", name, e);
	if (!status)
		status = KC_BACKEND->set_key(cipher->tfm, k, e);
	if (!status)
		status = KC_BACKEND->start(cipher->tfm, &cipher->op, e);
	if (!status)
		status = KC_BACKEND->set_op_iv(cipher->op, encrypt, iv, iv_len,
					       e);
	if (status) {
		kc_cipher_free(cipher);
		return status;
	}
	*c = cipher;
	return kc_ok(e);
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
		return status ? status : kc_ok(e);
	}

	if (c->part_len > 0 || !c->have_held)
		return kc_fail(e, KC_REFUSED, 0,
			       "bad decrypt (wrong final block length)");

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
	explicit_bzero(c, sizeof(*c));
	free(c);
}
