/*
 * craf-archive.h - craf archive format: header encoding and decoding
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

#ifndef CRAF_ARCHIVE_H
#define CRAF_ARCHIVE_H

#include <stdbool.h>
#include <stdint.h>
#include "craf.h"

struct craf_key_source;
struct craf_keys;

/* A header being written, at most UINT16_MAX bytes */
struct craf_wbuf {
	uint8_t data[UINT16_MAX];
	size_t len;
	bool overflow;
};

/* A header being read: the next field, and the first one that failed */
struct craf_rbuf {
	const uint8_t *data;
	size_t len;
	size_t pos;
	const char *field;
	const char *why;
};

struct craf_header {
	uint16_t format;
	uint16_t hdr_len;
	char cipher_driver[CRAF_STR_MAX + 1];
	char cipher_algo[CRAF_STR_MAX + 1];
	uint8_t key_len;
	char key_source[CRAF_STR_MAX + 1];
	uint8_t iv[CRAF_IV_LEN];
};

/* Little-endian integers; a string is its length in one byte, then ASCII */
extern void craf_put_bytes(struct craf_wbuf *b, const void *p, size_t len);
extern void craf_put_u8(struct craf_wbuf *b, uint8_t v);
extern void craf_put_u16(struct craf_wbuf *b, uint16_t v);
extern void craf_put_str(struct craf_wbuf *b, const char *s);
extern bool craf_get_bytes(struct craf_rbuf *r, const char *field,
			   void *p, size_t len);
extern bool craf_get_u8(struct craf_rbuf *r, const char *field, uint8_t *v);
extern bool craf_get_str(struct craf_rbuf *r, const char *field, char *s);

/* Both return a craf exit status, having reported a failure */
extern int craf_header_write(struct craf_wbuf *b, const struct craf_header *h,
			     const struct craf_key_source *src,
			     struct craf_keys *keys);
extern int craf_header_read(FILE *in, struct craf_wbuf *b,
			    struct craf_header *h,
			    const struct craf_key_source **src,
			    struct craf_keys *keys);

#endif /* CRAF_ARCHIVE_H */
