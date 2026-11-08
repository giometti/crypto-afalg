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

/*
 * What a keyring search looked for and the key it found; whether the
 * kernel compares that description as a string; a keyring of the
 * library's own to ask the kernel in, made at the first key to ask about;
 * and the first key the library could not examine, with why
 */
struct key_match {
	const char *type;
	const char *desc;
	bool by_string;
	key_serial_t found;
	key_serial_t probe;
	char probe_desc[32];
	int probe_err;
	key_serial_t unchecked;
	int err;
};

/*
 * The types whose search compares other than the description with
 * strcmp(), from their match_preparse() in the kernel (Linux 6.18): with
 * one of the prefixes, or with any description when there are none. Any
 * other type, and these with another description, the kernel compares by
 * key_default_cmp(), as a string.
 */
static const struct {
	const char *type;
	const char *prefixes[4];
} other_match_types[] = {
	{ "asymmetric",		{ "id:", "ex:", "dn:", NULL } },
	{ "dns_resolver",	{ NULL } },
	{ "psk",		{ NULL } },
};

static bool matched_by_string(const char *type, const char *desc)
{
	size_t i, j;

	for (i = 0; i < sizeof(other_match_types) /
			sizeof(other_match_types[0]); i++) {
		if (strcmp(type, other_match_types[i].type) != 0)
			continue;
		if (!other_match_types[i].prefixes[0])
			return false;
		for (j = 0; other_match_types[i].prefixes[j]; j++)
			if (strncmp(desc, other_match_types[i].prefixes[j],
				    strlen(other_match_types[i].prefixes[j])) == 0)
				return false;
	}
	return true;
}

/* errnos of a key the kernel's search passes over: not a match */
static bool search_skips(int err)
{
	return err == ENOKEY || err == EKEYEXPIRED || err == EKEYREVOKED;
}

/* The first key that could not be examined is the one told */
static void unchecked(struct key_match *m, key_serial_t key, int err)
{
	if (!m->unchecked) {
		m->unchecked = key;
		m->err = err;
	}
}

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
 * One more key that the search finds, besides the one found: desc is
 * "<type>;<uid>;<gid>;<perm>;<description>", NULL when it could not be
 * read. A description the kernel compares as a string is compared here;
 * otherwise the kernel is asked, by searching the probe with only that
 * key linked into it. A key that cannot be examined is told after the
 * scan, which still counts the keys found twice.
 */
static int other_match(key_serial_t parent, key_serial_t key, char *desc,
		       int desc_len, void *data)
{
	struct key_match *m = data;
	size_t tlen = strlen(m->type);
	char *buf, *p, *end;
	long found;
	int i, err, ret;

	if (key == m->found)
		return 0;
	if (!desc) {
		if (keyctl_describe_alloc(key, &buf) < 0) {
			if (!search_skips(errno))
				unchecked(m, key, errno);
			return 0;
		}
		ret = other_match(parent, key, buf, strlen(buf), data);
		free(buf);
		return ret;
	}
	if ((size_t) desc_len <= tlen || memcmp(desc, m->type, tlen) != 0 ||
	    desc[tlen] != ';')
		return 0;
	if (m->by_string) {
		p = desc;
		end = desc + desc_len;
		for (i = 0; i < 4; i++) {
			p = memchr(p, ';', end - p);
			if (!p)
				return 0;
			p++;
		}
		return is_name(p, end - p, m->desc);
	}

	if (m->probe_err) {
		unchecked(m, key, m->probe_err);
		return 0;
	}
	if (!m->probe) {
		m->probe = add_key("keyring", m->probe_desc, NULL, 0,
				   KEY_SPEC_THREAD_KEYRING);
		if (m->probe < 0) {
			m->probe = 0;
			m->probe_err = errno;
			unchecked(m, key, errno);
			return 0;
		}
	}
	if (keyctl_link(key, m->probe) < 0) {
		unchecked(m, key, errno);
		return 0;
	}
	found = keyctl_search(m->probe, m->type, m->desc, 0);
	err = errno;
	if (found < 0 && !search_skips(err) && err != EACCES)
		unchecked(m, key, err);
	if (keyctl_unlink(key, m->probe) < 0)
		unchecked(m, key, errno);
	return found == key;
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
	int i, n, err, status;

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
	 * keyrings the caller can read are counted; the probe is unique while
	 * m lives, as the keys of kc_key_blob() are.
	 */
	memset(&m, 0, sizeof(m));
	m.type = type;
	m.desc = pdesc;
	m.by_string = matched_by_string(type, pdesc);
	m.found = num;
	snprintf(m.probe_desc, sizeof(m.probe_desc), "kcrypto:%p",
		 (void *) &m);
	n = recursive_key_scan(keyring_id, other_match, &m);
	if (m.probe)
		keyctl_invalidate(m.probe);	/* intentionally ignored */
	if (n > 0)
		return kc_fail(e, KC_USAGE, ENOTUNIQ,
			       "more than one %s key %s in keyring %s",
			       type, pdesc, keyrings[i].shown);
	if (m.probe_err)
		return kc_fail(e, KC_FAILED, m.probe_err,
			       "cannot make a keyring to search in: %s",
			       strerror(m.probe_err));
	if (m.unchecked)
		return kc_fail(e, KC_FAILED, m.err,
			       "cannot tell whether the key %d is also %s key "
			       "%s: %s", m.unchecked, type, pdesc,
			       strerror(m.err));

found:
	status = new_key(k, 0, e);
	if (status)
		return status;
	(*k)->type = KC_KEY_SERIAL;
	(*k)->serial = num;
	return kc_ok(e);
}

/*
 * A key of type into the keyring of the calling thread, described by the
 * address of its struct kc_key, unique while it lives: no two live keys
 * of a thread share a description, which the kernel would refuse for a
 * trusted key and settle for an asymmetric one by putting the second in
 * the place of the first
 */
static int load_key(struct kc_key **k, const char *type, const void *payload,
		    size_t len, const char *what, struct kc_error *e)
{
	char desc[32];
	int err, status;

	status = new_key(k, 0, e);
	if (status)
		return status;
	snprintf(desc, sizeof(desc), "kcrypto:%p", (void *) *k);
	(*k)->serial = add_key(type, desc, payload, len,
			       KEY_SPEC_THREAD_KEYRING);
	if ((*k)->serial < 0) {
		err = errno;
		free(*k);
		*k = NULL;
		return kc_fail(e, KC_FAILED, err, "cannot load %s: %s", what,
			       strerror(err));
	}
	(*k)->type = KC_KEY_SERIAL;
	(*k)->loaded = true;
	return kc_ok(e);
}

KC_EXPORT int kc_key_blob(struct kc_key **k, const void *blob, size_t len,
			  struct kc_error *e)
{
	static const char digits[] = "0123456789abcdef";
	const unsigned char *b = blob;
	size_t plen = strlen("load "), i;
	char *payload;
	int status;

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
	status = load_key(k, "trusted", payload, plen, "the trusted key blob",
			  e);
	explicit_bzero(payload, plen);
	free(payload);
	return status;
}

KC_EXPORT int kc_key_cert(struct kc_key **k, const void *der, size_t len,
			  struct kc_error *e)
{
	*k = NULL;
	if (len == 0)
		return kc_fail(e, KC_USAGE, EINVAL, "empty certificate");
	return load_key(k, "asymmetric", der, len, "the certificate", e);
}

KC_EXPORT int kc_key_pubkey(struct kc_key **k, const void *spki, size_t len,
			    struct kc_error *e)
{
	unsigned char *der;
	size_t der_len;
	int status;

	*k = NULL;
	status = kc_x509_wrap(spki, len, &der, &der_len, e);
	if (status)
		return status;
	status = load_key(k, "asymmetric", der, der_len,
			  "the certificate of the public key", e);
	free(der);
	return status;
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

KC_EXPORT int kc_key_is_keycrypt(const struct kc_key *k, struct kc_error *e)
{
	size_t tlen = strlen(KC_KEYCRYPT_TYPE);
	char *buf;
	bool keycrypt;
	int err;

	if (!k)
		return kc_fail(e, KC_USAGE, EINVAL, "no key");
	if (k->type != KC_KEY_SERIAL)
		return kc_fail(e, KC_REFUSED, 0,
			       "a key in clear is not a keycrypt key");
	if (keyctl_describe_alloc(k->serial, &buf) < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err,
			       "cannot tell whether the key %d is a keycrypt key: %s",
			       k->serial, strerror(err));
	}
	keycrypt = strncmp(buf, KC_KEYCRYPT_TYPE, tlen) == 0 &&
		   buf[tlen] == ';';
	free(buf);
	if (!keycrypt)
		return kc_fail(e, KC_REFUSED, 0,
			       "the key %d is not a keycrypt key", k->serial);
	return kc_ok(e);
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
