/*
 * kc-key.c - keys: raw bytes, or a keyring key by serial (libkcrypto)
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
#include <keyutils.h>
#include "kc-internal.h"
#include "kc-backend.h"

/* What a keyring search looked for, and the key it found */
struct key_match {
	const char *type;
	const char *desc;
	key_serial_t found;
};

/* The keyrings a spec may name, each by one of two exact names */
static const struct {
	const char *names[2];
	key_serial_t id;
	const char *shown;
} keyrings[] = {
	{ { "@u", "user" },	KEY_SPEC_USER_KEYRING,		"@u" },
	{ { "@s", "session" },	KEY_SPEC_SESSION_KEYRING,	"@s" },
};

static bool is_name(const char *s, size_t len, const char *name)
{
	return strlen(name) == len && memcmp(s, name, len) == 0;
}

/* The index in keyrings[] of the keyring named by s, len long, or -1 */
static int keyring_by_name(const char *s, size_t len)
{
	size_t i, j;

	for (i = 0; i < sizeof(keyrings) / sizeof(keyrings[0]); i++)
		for (j = 0; j < 2; j++)
			if (is_name(s, len, keyrings[i].names[j]))
				return i;
	return -1;
}

/* Decimal digits only, positive and within key_serial_t */
static bool parse_serial(const char *s, key_serial_t *id)
{
	char *end;
	long v;

	if (*s < '0' || *s > '9')
		return false;
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno || *end != '\0' || v <= 0 || v > INT32_MAX)
		return false;
	*id = v;
	return true;
}

/*
 * One more key of the type and description searched, besides the one
 * found: desc is "<type>;<uid>;<gid>;<perm>;<description>"
 */
static int other_match(key_serial_t parent, key_serial_t key, char *desc,
		       int desc_len, void *data)
{
	const struct key_match *m = data;
	size_t tlen = strlen(m->type);
	char *p, *end;
	int i;

	if (!desc || key == m->found)
		return 0;
	p = desc;
	end = desc + desc_len;
	if ((size_t) desc_len <= tlen || memcmp(p, m->type, tlen) != 0 ||
	    p[tlen] != ';')
		return 0;
	for (i = 0; i < 4; i++) {
		p = memchr(p, ';', end - p);
		if (!p)
			return 0;
		p++;
	}
	return is_name(p, end - p, m->desc);
}

static int new_key(struct kc_key **k, size_t len, struct kc_error *e)
{
	*k = calloc(1, sizeof(**k) + len);
	if (!*k)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	return KC_OK;
}

KC_EXPORT int kc_key_raw(struct kc_key **k, const void *data, size_t len,
			 struct kc_error *e)
{
	int status;

	status = new_key(k, len, e);
	if (status)
		return status;
	(*k)->type = KC_KEY_RAW;
	(*k)->len = len;
	if (len > 0)
		memcpy((*k)->data, data, len);
	return kc_ok(e);
}

KC_EXPORT int kc_key_spec(struct kc_key **k, const char *spec,
			  struct kc_error *e)
{
	const char *ptype, *pdesc, *comma;
	struct key_match m;
	key_serial_t keyring_id, num;
	char type[64];
	int i, err, status;

	*k = NULL;

	/* The simple form "<serial>" */
	comma = strchr(spec, ',');
	if (!comma) {
		if (!parse_serial(spec, &num))
			return kc_fail(e, KC_USAGE, EINVAL,
				       "invalid key serial number \"%s\"",
				       spec);
		goto found;
	}

	/* The form "[<keyring>,]<type>,<description>", @u by default */
	i = 0;
	ptype = spec;
	pdesc = strchr(comma + 1, ',');
	if (pdesc) {
		i = keyring_by_name(spec, comma - spec);
		if (i < 0)
			return kc_fail(e, KC_USAGE, EINVAL,
				       "unknown keyring name \"%.*s\"",
				       (int) (comma - spec), spec);
		ptype = comma + 1;
	} else
		pdesc = comma;

	if (pdesc == ptype)
		return kc_fail(e, KC_USAGE, EINVAL,
			       "empty key type in \"%s\"", spec);
	if ((size_t) (pdesc - ptype) >= sizeof(type))
		return kc_fail(e, KC_USAGE, EINVAL, "key type too long");
	memcpy(type, ptype, pdesc - ptype);
	type[pdesc - ptype] = '\0';
	pdesc++;
	if (*pdesc == '\0')
		return kc_fail(e, KC_USAGE, EINVAL,
			       "empty key description in \"%s\"", spec);

	keyring_id = keyctl_get_keyring_ID(keyrings[i].id, 0);
	if (keyring_id < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "cannot get keyring ID: %s",
			       strerror(err));
	}
	/* EINVAL: a type or a description the kernel finds too long */
	num = keyctl_search(keyring_id, type, pdesc, 0);
	if (num < 0) {
		err = errno;
		return kc_fail(e, err == EINVAL ? KC_USAGE : KC_FAILED, err,
			       "cannot get ID for %s key %s in keyring %s: %s",
			       type, pdesc, keyrings[i].shown, strerror(err));
	}

	/*
	 * The search descends into the keyrings linked to this one and takes
	 * the first key it meets, so a name held twice is refused. Only the
	 * keyrings the caller can read are counted.
	 */
	m.type = type;
	m.desc = pdesc;
	m.found = num;
	if (recursive_key_scan(keyring_id, other_match, &m) > 0)
		return kc_fail(e, KC_USAGE, ENOTUNIQ,
			       "more than one %s key %s in keyring %s",
			       type, pdesc, keyrings[i].shown);

found:
	status = new_key(k, 0, e);
	if (status)
		return status;
	(*k)->type = KC_KEY_SERIAL;
	(*k)->serial = num;
	return kc_ok(e);
}

KC_EXPORT int kc_key_blob(struct kc_key **k, const void *blob, size_t len,
			  struct kc_error *e)
{
	static const char digits[] = "0123456789abcdef";
	const unsigned char *b = blob;
	char desc[32], *payload;
	size_t plen = strlen("load "), i;
	int err, status;

	*k = NULL;
	if (len == 0)
		return kc_fail(e, KC_USAGE, EINVAL, "empty key blob");
	if (len > (SIZE_MAX - plen) / 2)
		return kc_fail(e, KC_USAGE, E2BIG, "key blob too long");
	payload = malloc(plen + 2 * len);
	if (!payload)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	memcpy(payload, "load ", plen);
	for (i = 0; i < len; i++) {
		payload[plen++] = digits[b[i] >> 4];
		payload[plen++] = digits[b[i] & 0xf];
	}

	/*
	 * A second key with the description of one in the keyring is
	 * refused: the address of the key, unique while it lives, tells
	 * apart the keys of one thread
	 */
	status = new_key(k, 0, e);
	if (!status) {
		snprintf(desc, sizeof(desc), "kcrypto:%p", (void *) *k);
		(*k)->serial = add_key("trusted", desc, payload, plen,
				       KEY_SPEC_THREAD_KEYRING);
		err = errno;
		if ((*k)->serial < 0) {
			free(*k);
			*k = NULL;
			status = kc_fail(e, KC_FAILED, err,
					 "cannot load the trusted key blob: %s",
					 strerror(err));
		}
	}
	explicit_bzero(payload, plen);
	free(payload);
	if (status)
		return status;
	(*k)->type = KC_KEY_SERIAL;
	(*k)->loaded = true;
	return kc_ok(e);
}

KC_EXPORT int kc_key_unload(struct kc_key *k, struct kc_error *e)
{
	int err;

	if (!k || !k->loaded)
		return kc_ok(e);
	if (keyctl_invalidate(k->serial) < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err,
			       "cannot remove the key %d: %s", k->serial,
			       strerror(err));
	}
	k->loaded = false;
	return kc_ok(e);
}

KC_EXPORT int32_t kc_key_serial(const struct kc_key *k)
{
	return k->type == KC_KEY_SERIAL ? k->serial : 0;
}

KC_EXPORT int kc_key_serial_supported(void)
{
	return KC_BACKEND->key_serial;
}

KC_EXPORT void kc_key_free(struct kc_key *k)
{
	if (!k)
		return;
	if (k->loaded)
		keyctl_invalidate(k->serial);	/* intentionally ignored */
	explicit_bzero(k->data, k->len);
	free(k);
}
