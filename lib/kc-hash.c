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
