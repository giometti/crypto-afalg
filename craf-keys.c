/*
 * craf-keys.c - craf key sources
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
#include <stdlib.h>
#include <string.h>
#include <keyutils.h>
#include "craf-keys.h"

/* A trusted key blob, as long as the length of its header field counts */
#define BLOB_MAX		UINT16_MAX

/* The state of source "trusted": the blob of its key */
struct trusted {
	uint8_t blob[BLOB_MAX];
	uint16_t len;
};

int craf_describe_err(const char *opt, const struct kc_key *key, int err)
{
	return craf_err(CRAF_FAILED, "%s: cannot describe key %d: %s", opt,
			kc_key_serial(key), strerror(err));
}

/*
 * A user key can be read back, so its length is checked: one of 16 or
 * 24 bytes would make the cipher AES-128 or AES-192 in silence.
 */
int craf_check_user_key(const char *opt, const struct kc_key *key,
			size_t want, bool *checked)
{
	key_serial_t id = kc_key_serial(key);
	char *desc;
	long len;
	bool user;

	if (keyctl_describe_alloc(id, &desc) < 0)
		return craf_describe_err(opt, key, errno);
	user = strncmp(desc, "user;", 5) == 0;
	free(desc);
	if (checked)
		*checked = user;
	if (!user)
		return CRAF_OK;
	len = keyctl_read(id, NULL, 0);
	if (len < 0)
		return craf_err(CRAF_FAILED, "%s: cannot read key %d: %m",
				opt, id);
	if (len != (long) want)
		return craf_err(CRAF_USAGE, "%s: user key %d is %ld bytes, not %zu",
				opt, id, len, want);
	return CRAF_OK;
}

int craf_find_key(const char *opt, const char *spec, struct kc_key **key)
{
	struct kc_error e;
	int status;

	/* A malformed or an ambiguous spec, or a key not there */
	status = kc_key_spec(key, spec, &e);
	if (status)
		return craf_err(status == KC_USAGE ? CRAF_USAGE : CRAF_FAILED,
				"%s: %s", opt, e.msg);
	return CRAF_OK;
}

/*
 * Source "serial": a keyring key of the caller, which it owns, so the
 * header holds nothing of it and nothing is released
 */
static int serial_keys(const struct craf_key_opts *opts,
		       struct craf_keys *keys)
{
	int status;

	status = craf_find_key("-enc-key", opts->enc_key, &keys->enc);

	/* Keycrypt brings the length, and asks no View of the key */
	if (!status && !opts->keycrypt)
		status = craf_check_user_key("-enc-key", keys->enc,
					     CRAF_KEY_LEN, NULL);
	return status;
}

static int serial_write_fields(struct craf_wbuf *b, struct craf_keys *keys)
{
	return CRAF_OK;
}

static int serial_read_fields(struct craf_rbuf *r, struct craf_keys *keys)
{
	return CRAF_OK;
}

static void serial_print_fields(FILE *out, const struct craf_keys *keys)
{
}

static void serial_release(struct craf_keys *keys)
{
}

static const struct craf_key_source serial_source = {
	.name		= "serial",
	.key_in_header	= false,
	.seal_keys	= serial_keys,
	.write_fields	= serial_write_fields,
	.read_fields	= serial_read_fields,
	.unseal_keys	= serial_keys,
	.print_fields	= serial_print_fields,
	.release	= serial_release,
};

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* The blob in hex, as keyctl pipe writes it, or print with a newline */
static int read_blob(const char *path, struct trusted *t)
{
	/* One more than the longest, to tell a longer file */
	static char hex[2 * BLOB_MAX + 2];
	size_t n, i;
	int hi, lo;
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		return craf_err(CRAF_FAILED, "-enc-blob: cannot open %s: %m",
				path);
	n = fread(hex, 1, sizeof(hex), f);
	if (ferror(f)) {
		err("-enc-blob: cannot read %s: %m", path);
		fclose(f);
		return CRAF_FAILED;
	}
	fclose(f);
	if (n > 0 && hex[n - 1] == '\n')
		n--;
	if (n > 2 * BLOB_MAX)
		return craf_err(CRAF_USAGE,
				"-enc-blob: %s holds a blob longer than %d bytes",
				path, BLOB_MAX);
	if (n == 0)
		return craf_err(CRAF_USAGE, "-enc-blob: %s is empty", path);
	if (n % 2)
		return craf_err(CRAF_USAGE,
				"-enc-blob: %s is not a key blob in hex", path);
	for (i = 0; i < n; i += 2) {
		hi = hex_value(hex[i]);
		lo = hex_value(hex[i + 1]);
		if (hi < 0 || lo < 0)
			return craf_err(CRAF_USAGE,
					"-enc-blob: %s is not a key blob in hex",
					path);
		t->blob[i / 2] = hi << 4 | lo;
	}
	t->len = n / 2;
	return CRAF_OK;
}

/*
 * What the kernel loads is the blob the header holds, in the kernel's
 * own form. The key has the length it was made with, which craf cannot
 * read: 32 bytes is up to whoever made it. A blob that needs options to
 * load, such as a TPM 2.0 policy, cannot be used. path names the
 * -enc-blob file, NULL for the blob an archive carries.
 */
static int load_blob(struct trusted *t, const char *path, struct kc_key **key)
{
	struct kc_error e;
	const char *hint;

	if (!kc_key_blob(key, t->blob, t->len, &e))
		return CRAF_OK;
	/* ENODEV: no "trusted" key type is registered */
	hint = e.errnum == ENODEV ?
		"no trusted keys in the kernel, or no trust source up" :
		"sealed on another system, or changed?";
	if (path)
		return craf_err(CRAF_FAILED,
				"-enc-blob: cannot load the trusted key blob in %s: %s (%s)",
				path, strerror(e.errnum), hint);
	return craf_err(CRAF_FAILED,
			"cannot load the trusted key blob the archive carries: %s (%s)",
			strerror(e.errnum), hint);
}

static int trusted_state(struct craf_keys *keys, struct trusted **t)
{
	*t = calloc(1, sizeof(**t));
	if (!*t)
		return craf_err(CRAF_FAILED, "cannot allocate memory: %m");
	keys->priv = *t;
	return CRAF_OK;
}

/*
 * Source "trusted": the blob of a trusted key, which only the trust
 * source that made it can load, travels in the header
 */
static int trusted_seal_keys(const struct craf_key_opts *opts,
			     struct craf_keys *keys)
{
	struct trusted *t;
	int status;

	status = trusted_state(keys, &t);
	if (!status)
		status = read_blob(opts->enc_blob, t);
	if (!status)
		status = load_blob(t, opts->enc_blob, &keys->enc);
	return status;
}

static int trusted_write_fields(struct craf_wbuf *b, struct craf_keys *keys)
{
	struct trusted *t = keys->priv;

	craf_put_blob(b, t->blob, t->len);
	return CRAF_OK;
}

static int trusted_read_fields(struct craf_rbuf *r, struct craf_keys *keys)
{
	struct trusted *t;
	int status;

	status = trusted_state(keys, &t);
	if (status)
		return status;
	/* A wrong field stays in r: the header reader reports it */
	craf_get_blob(r, "blob", t->blob, &t->len);
	return CRAF_OK;
}

static int trusted_unseal_keys(const struct craf_key_opts *opts,
			       struct craf_keys *keys)
{
	return load_blob(keys->priv, NULL, &keys->enc);
}

/*
 * The blob is the key for whoever has the trust source, and the output of
 * info goes where the archive does not: its length only
 */
static void trusted_print_fields(FILE *out, const struct craf_keys *keys)
{
	const struct trusted *t = keys->priv;

	fprintf(out, "blob_len: %u\n", (unsigned) t->len);
}

static void trusted_release(struct craf_keys *keys)
{
	free(keys->priv);
	keys->priv = NULL;
}

static const struct craf_key_source trusted_source = {
	.name		= "trusted",
	.key_in_header	= true,
	.seal_keys	= trusted_seal_keys,
	.write_fields	= trusted_write_fields,
	.read_fields	= trusted_read_fields,
	.unseal_keys	= trusted_unseal_keys,
	.print_fields	= trusted_print_fields,
	.release	= trusted_release,
};

static const struct craf_key_source *const sources[] = {
	&serial_source,
	&trusted_source,
};

int craf_seal_source(const struct craf_key_opts *opts,
		     const struct craf_key_source **src)
{
	*src = opts->enc_blob ? &trusted_source : &serial_source;
	return CRAF_OK;
}

/* Which key option unseal takes depends on the archive */
int craf_unseal_key_opts(const struct craf_key_source *src,
			 const struct craf_key_opts *opts)
{
	if (src->key_in_header && opts->enc_key)
		return craf_err(CRAF_USAGE, "unseal: the archive carries its "
				"key, -enc-key is not for it");
	if (!src->key_in_header && !opts->enc_key)
		return craf_err(CRAF_USAGE,
				"unseal: the archive needs -enc-key");
	return CRAF_OK;
}

const struct craf_key_source *craf_key_source_by_name(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(sources); i++)
		if (strcmp(sources[i]->name, name) == 0)
			return sources[i];
	return NULL;
}

/*
 * A key the library loaded that it cannot take out of the keyring is not
 * fatal: the thread keyring goes at the exit anyway
 */
void craf_release_keys(const struct craf_key_source *src,
		       struct craf_keys *keys)
{
	struct kc_error e;

	src->release(keys);
	if (kc_key_unload(keys->enc, &e))
		err("cannot remove the trusted key %d: %s",
		    kc_key_serial(keys->enc), strerror(e.errnum));
	kc_key_free(keys->enc);
	keys->enc = NULL;
}
