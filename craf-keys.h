/*
 * craf-keys.h - craf key sources
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

#ifndef CRAF_KEYS_H
#define CRAF_KEYS_H

#include "craf-archive.h"

/* What the command line says of the key */
struct craf_key_opts {
	const char *enc_key;		/* -enc-key */
	const char *enc_blob;		/* seal -enc-blob */
	bool keycrypt;			/* the key goes to keycrypt */
};

/* The key of an archive, ready for kc_cipher_open() */
struct craf_keys {
	struct kc_key *enc;
	void *priv;			/* the key source's own state */
};

/*
 * Where the key comes from. The archive format and the two streams do
 * not depend on it: a new source is one more of these. Each function
 * returns a craf exit status, having reported a failure; release() frees
 * the source's own state, whatever happened before, once the source is
 * chosen, through craf_release_keys(), which frees the key too.
 */
struct craf_key_source {
	const char *name;		/* key_source in the header */
	bool key_in_header;		/* unseal takes no key option */
	int (*seal_keys)(const struct craf_key_opts *opts,
			 struct craf_keys *keys);
	int (*write_fields)(struct craf_wbuf *b, struct craf_keys *keys);
	int (*read_fields)(struct craf_rbuf *r, struct craf_keys *keys);
	int (*unseal_keys)(const struct craf_key_opts *opts,
			   struct craf_keys *keys);
	/* craf info: what read_fields() read, one "name: value" a line */
	void (*print_fields)(FILE *out, const struct craf_keys *keys);
	void (*release)(struct craf_keys *keys);
};

/* A keyring key by its spec or serial, as the option opt gives it */
extern int craf_find_key(const char *opt, const char *spec,
			 struct kc_key **key);
extern int craf_seal_source(const struct craf_key_opts *opts,
			    const struct craf_key_source **src);
extern int craf_unseal_key_opts(const struct craf_key_source *src,
				const struct craf_key_opts *opts);
extern const struct craf_key_source *craf_key_source_by_name(const char *name);
extern void craf_release_keys(const struct craf_key_source *src,
			      struct craf_keys *keys);

#endif /* CRAF_KEYS_H */
