/*
 * kc-pkey.c - asymmetric keyring keys, through keyctl (libkcrypto)
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
#include <string.h>
#include <keyutils.h>
#include "kc-internal.h"
#include "kc-backend.h"

/* KC_PKEY_* are the kernel's bits, so the query's mask is taken as it is */
_Static_assert(KC_PKEY_ENCRYPT == KEYCTL_SUPPORTS_ENCRYPT &&
	       KC_PKEY_DECRYPT == KEYCTL_SUPPORTS_DECRYPT &&
	       KC_PKEY_SIGN == KEYCTL_SUPPORTS_SIGN &&
	       KC_PKEY_VERIFY == KEYCTL_SUPPORTS_VERIFY,
	       "KC_PKEY_* differ from KEYCTL_SUPPORTS_*");

KC_EXPORT int kc_pkey_query(const struct kc_key *k, const char *params,
			    struct kc_pkey_info *info, struct kc_error *e)
{
	struct keyctl_pkey_query q;
	int err;

	if (!k || k->type != KC_KEY_SERIAL)
		return kc_fail(e, KC_USAGE, EINVAL, "not a keyring key");
	if (!params)
		return kc_fail(e, KC_USAGE, EINVAL, "no parameters");
	if (!info)
		return kc_fail(e, KC_USAGE, EINVAL, "no room for the answer");
	memset(&q, 0, sizeof(q));
	if (keyctl_pkey_query(k->serial, params, &q) < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err,
			       "cannot query the key %d with \"%s\": %s",
			       k->serial, params, strerror(err));
	}
	memset(info, 0, sizeof(*info));
	info->ops = q.supported_ops & (KC_PKEY_ENCRYPT | KC_PKEY_DECRYPT |
				       KC_PKEY_SIGN | KC_PKEY_VERIFY);
	info->key_size = q.key_size;
	info->max_data = q.max_data_size;
	info->max_sig = q.max_sig_size;
	info->max_enc = q.max_enc_size;
	info->max_dec = q.max_dec_size;
	return kc_ok(e);
}

/*
 * The kernel gives EINVAL for a signature that does not hold as for a
 * call it does not take: the query, with the same parameters, and the
 * checks of the lengths leave it the first meaning only
 */
KC_EXPORT int kc_pkey_verify(const struct kc_key *k, const char *params,
			     const void *digest, size_t digest_len,
			     const void *sig, size_t sig_len,
			     struct kc_error *e)
{
	struct kc_pkey_info info;
	int err, status;

	status = kc_pkey_query(k, params, &info, e);
	if (status)
		return status;
	if (!(info.ops & KC_PKEY_VERIFY))
		return kc_fail(e, KC_FAILED, EOPNOTSUPP,
			       "the key %d cannot verify with \"%s\"",
			       k->serial, params);
	if (digest_len == 0 || digest_len > info.max_data)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "a digest of %zu bytes, the key takes 1 to %zu",
			       digest_len, info.max_data);
	if (sig_len == 0)
		return kc_fail(e, KC_USAGE, EINVAL, "empty signature");
	if (sig_len > info.max_sig)
		return kc_fail(e, KC_REFUSED, 0,
			       "verification failure: a signature of %zu "
			       "bytes, the key's are at most %zu", sig_len,
			       info.max_sig);
	if (keyctl_pkey_verify(k->serial, params, digest, digest_len, sig,
			       sig_len) < 0) {
		err = errno;
		if (err == EKEYREJECTED || err == EBADMSG || err == EINVAL)
			return kc_fail(e, KC_REFUSED, err,
				       "verification failure: %s",
				       strerror(err));
		return kc_fail(e, KC_FAILED, err,
			       "cannot verify with the key %d: %s", k->serial,
			       strerror(err));
	}
	return kc_ok(e);
}
