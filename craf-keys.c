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

/*
 * A user key can be read back, so its length is checked: one of 16 or
 * 24 bytes would make the cipher AES-128 or AES-192 in silence.
 */
static int check_user_key(const char *opt, key_serial_t id)
{
	char *desc;
	long len;
	bool user;

	if (keyctl_describe_alloc(id, &desc) < 0)
		return craf_err(CRAF_FAILED, "%s: cannot describe key %d: %m",
				opt, id);
	user = strncmp(desc, "user;", 5) == 0;
	free(desc);
	if (!user)
		return CRAF_OK;
	len = keyctl_read(id, NULL, 0);
	if (len < 0)
		return craf_err(CRAF_FAILED, "%s: cannot read key %d: %m",
				opt, id);
	if (len != CRAF_KEY_LEN)
		return craf_err(CRAF_USAGE, "%s: user key %d is %ld bytes, not %d",
				opt, id, len, CRAF_KEY_LEN);
	return CRAF_OK;
}

static int resolve(const char *opt, const char *spec, struct afalg_key *key)
{
	char msg[1024];
	int status;

	if (afalg_key_from_spec(spec, key, msg, sizeof(msg)) < 0) {
		/* A malformed or an ambiguous spec, or a key not there */
		status = errno == EINVAL || errno == ENOTUNIQ ? CRAF_USAGE :
			 CRAF_FAILED;
		return craf_err(status, "%s: %s", opt, msg);
	}
	return check_user_key(opt, key->serial);
}

/*
 * Source "serial": a keyring key of the caller, which it owns, so the
 * header holds nothing of it and nothing is released
 */
static int serial_keys(const struct craf_key_opts *opts,
		       struct craf_keys *keys)
{
	return resolve("-enc-key", opts->enc_key, &keys->enc);
}

static int serial_write_fields(struct craf_wbuf *b, struct craf_keys *keys)
{
	return CRAF_OK;
}

static int serial_read_fields(struct craf_rbuf *r, struct craf_keys *keys)
{
	return CRAF_OK;
}

static void serial_release(struct craf_keys *keys)
{
}

static const struct craf_key_source serial_source = {
	.name		= "serial",
	.seal_keys	= serial_keys,
	.write_fields	= serial_write_fields,
	.read_fields	= serial_read_fields,
	.unseal_keys	= serial_keys,
	.release	= serial_release,
};

static const struct craf_key_source *const sources[] = {
	&serial_source,
};

int craf_seal_source(const struct craf_key_opts *opts,
		     const struct craf_key_source **src)
{
	*src = &serial_source;
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
