/*
 * kc-hash.c - hashes and HMACs (libkcrypto)
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

struct kc_hash {
	struct kc_tfm *tfm;
	struct kc_op *op;
	bool done;		/* the kernel would start a new hash */
};

KC_EXPORT int kc_hash_open(struct kc_hash **h, const char *name,
			   const struct kc_key *k, struct kc_error *e)
{
	struct kc_hash *hash;
	int status;

	*h = NULL;
	hash = calloc(1, sizeof(*hash));
	if (!hash)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	status = KC_BACKEND->open(&hash->tfm, "hash", name, e);
	if (!status && k)
		status = KC_BACKEND->set_key(hash->tfm, k, e);
	if (!status)
		status = KC_BACKEND->start(hash->tfm, &hash->op, e);
	if (status) {
		kc_hash_free(hash);
		return status;
	}
	*h = hash;
	return kc_ok(e);
}

KC_EXPORT int kc_hash_update(struct kc_hash *h, const void *in, size_t len,
			     struct kc_error *e)
{
	int status;

	if (h->done)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "the hash cannot be used any more");
	status = KC_BACKEND->send(h->op, in, len, e);
	if (status)
		h->done = true;
	return status;
}

/*
 * The read ends the hash in the kernel also when the room is too small:
 * one more would give the digest of a new, empty, hash
 */
KC_EXPORT int kc_hash_final(struct kc_hash *h, void *md, size_t *md_len,
			    struct kc_error *e)
{
	if (h->done)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "the hash cannot be used any more");
	h->done = true;
	return KC_BACKEND->recv(h->op, md, *md_len, md_len, e);
}

/* One HMAC, its key already set: a, then b, through one operation */
static int hmac_once(struct kc_tfm *t, const void *a, size_t a_len,
		     const void *b, size_t b_len, unsigned char *md,
		     size_t *md_len, struct kc_error *e)
{
	struct kc_op *op;
	int status;

	status = KC_BACKEND->start(t, &op, e);
	if (status)
		return status;
	status = KC_BACKEND->send(op, a, a_len, e);
	if (!status)
		status = KC_BACKEND->send(op, b, b_len, e);
	if (!status)
		status = KC_BACKEND->recv(op, md, KC_HASH_MAX, md_len, e);
	KC_BACKEND->end(op);
	return status;
}

/*
 * The algorithm bound once, the passphrase its key, and one operation for
 * each HMAC: binding at every iteration would cost more than the HMAC
 */
KC_EXPORT int kc_pbkdf2(const char *hmac, const void *pass, size_t pass_len,
			const void *salt, size_t salt_len, unsigned int iter,
			void *out, size_t out_len, struct kc_error *e)
{
	unsigned char u[KC_HASH_MAX], t[KC_HASH_MAX], be[4];
	unsigned char *dst = out;
	struct kc_tfm *tfm = NULL;
	struct kc_key *k;
	uint32_t block;
	size_t u_len, n, j;
	unsigned int i;
	int status;

	if (iter == 0)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "PBKDF2 needs one iteration at least");
	if (out_len == 0)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "PBKDF2 needs one byte of output at least");
	status = kc_key_raw(&k, pass, pass_len, e);
	if (status)
		return status;
	status = KC_BACKEND->open(&tfm, "hash", hmac, e);
	if (!status)
		status = KC_BACKEND->set_key(tfm, k, e);
	kc_key_free(k);

	for (block = 1; !status && out_len > 0; block++) {
		be[0] = block >> 24;
		be[1] = block >> 16;
		be[2] = block >> 8;
		be[3] = block;
		status = hmac_once(tfm, salt, salt_len, be, sizeof(be), u,
				   &u_len, e);
		if (status)
			break;
		memcpy(t, u, u_len);
		for (i = 1; i < iter; i++) {
			status = hmac_once(tfm, u, u_len, NULL, 0, u, &u_len,
					   e);
			if (status)
				break;
			for (j = 0; j < u_len; j++)
				t[j] ^= u[j];
		}
		if (status)
			break;
		n = out_len < u_len ? out_len : u_len;
		memcpy(dst, t, n);
		dst += n;
		out_len -= n;
	}

	if (tfm)
		KC_BACKEND->close(tfm);
	explicit_bzero(u, sizeof(u));
	explicit_bzero(t, sizeof(t));
	return status ? status : kc_ok(e);
}

KC_EXPORT void kc_hash_free(struct kc_hash *h)
{
	if (!h)
		return;
	if (h->op)
		KC_BACKEND->end(h->op);
	if (h->tfm)
		KC_BACKEND->close(h->tfm);
	free(h);
}
