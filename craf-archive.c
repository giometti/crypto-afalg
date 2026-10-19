/*
 * craf-archive.c - craf archive format: header encoding and decoding
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

#include <string.h>
#include "craf-archive.h"
#include "craf-keys.h"

void craf_put_bytes(struct craf_wbuf *b, const void *p, size_t len)
{
	if (b->overflow || sizeof(b->data) - b->len < len) {
		b->overflow = true;
		return;
	}
	memcpy(b->data + b->len, p, len);
	b->len += len;
}

void craf_put_u8(struct craf_wbuf *b, uint8_t v)
{
	craf_put_bytes(b, &v, 1);
}

void craf_put_u16(struct craf_wbuf *b, uint16_t v)
{
	uint8_t le[2] = { v & 0xff, v >> 8 };

	craf_put_bytes(b, le, sizeof(le));
}

void craf_put_str(struct craf_wbuf *b, const char *s)
{
	size_t len = strlen(s);

	if (len > CRAF_STR_MAX) {
		b->overflow = true;
		return;
	}
	craf_put_u8(b, len);
	craf_put_bytes(b, s, len);
}

void craf_put_blob(struct craf_wbuf *b, const void *p, uint16_t len)
{
	craf_put_u16(b, len);
	craf_put_bytes(b, p, len);
}

static bool rbuf_fail(struct craf_rbuf *r, const char *field,
		      const char *why)
{
	if (!r->field) {
		r->field = field;
		r->why = why;
	}
	return false;
}

bool craf_get_bytes(struct craf_rbuf *r, const char *field, void *p,
		    size_t len)
{
	if (r->len - r->pos < len)
		return rbuf_fail(r, field, "runs past the header");
	memcpy(p, r->data + r->pos, len);
	r->pos += len;
	return true;
}

bool craf_get_u8(struct craf_rbuf *r, const char *field, uint8_t *v)
{
	return craf_get_bytes(r, field, v, 1);
}

/* Not empty, and printable ASCII without blanks */
bool craf_get_str(struct craf_rbuf *r, const char *field, char *s)
{
	uint8_t len;
	size_t i;

	if (!craf_get_u8(r, field, &len))
		return false;
	if (len == 0)
		return rbuf_fail(r, field, "is empty");
	if (!craf_get_bytes(r, field, s, len))
		return false;
	s[len] = '\0';
	for (i = 0; i < len; i++)
		if (s[i] < 0x21 || s[i] > 0x7e)
			return rbuf_fail(r, field, "is not printable ASCII");
	return true;
}

/* Not empty; the size of p lets gcc refuse a buffer that is too small */
bool craf_get_blob(struct craf_rbuf *r, const char *field,
		   uint8_t p[static UINT16_MAX], uint16_t *len)
{
	uint8_t le[2];

	if (!craf_get_bytes(r, field, le, sizeof(le)))
		return false;
	*len = le[0] | le[1] << 8;
	if (*len == 0)
		return rbuf_fail(r, field, "is empty");
	return craf_get_bytes(r, field, p, *len);
}

int craf_header_write(struct craf_wbuf *b, const struct craf_header *h,
		      const struct craf_key_source *src,
		      struct craf_keys *keys)
{
	int status;

	b->len = 0;
	b->overflow = false;
	craf_put_bytes(b, CRAF_MAGIC, CRAF_MAGIC_LEN);
	craf_put_u16(b, CRAF_FORMAT);
	craf_put_u16(b, 0);		/* hdr_len, known at the end */
	craf_put_str(b, h->cipher_driver);
	craf_put_str(b, h->cipher_algo);
	craf_put_u8(b, h->key_len);
	craf_put_str(b, src->name);
	craf_put_bytes(b, h->iv, CRAF_IV_LEN);
	status = src->write_fields(b, keys);
	if (status)
		return status;
	if (b->overflow)
		return craf_err(CRAF_FAILED, "archive header longer than %u bytes",
				UINT16_MAX);
	b->data[10] = b->len & 0xff;
	b->data[11] = b->len >> 8;
	return CRAF_OK;
}

/* Input that ends early is a truncated header */
static int read_exactly(FILE *in, uint8_t *p, size_t len)
{
	if (fread(p, 1, len, in) == len)
		return CRAF_OK;
	if (ferror(in))
		return craf_err(CRAF_FAILED, "cannot read input: %m");
	return craf_err(CRAF_REFUSED, "truncated header");
}

int craf_header_read(FILE *in, struct craf_wbuf *b, struct craf_header *h,
		     const struct craf_key_source **src,
		     struct craf_keys *keys)
{
	struct craf_rbuf r = {};
	int status;

	status = read_exactly(in, b->data, CRAF_PREFIX_LEN);
	if (status)
		return status;
	if (memcmp(b->data, CRAF_MAGIC, CRAF_MAGIC_LEN) != 0)
		return craf_err(CRAF_REFUSED, "not a craf archive");
	h->format = b->data[8] | b->data[9] << 8;
	/* A newer archive may be good: this craf could not read it */
	if (h->format > CRAF_FORMAT)
		return craf_err(CRAF_FAILED,
				"version %u needs a newer craf, this one reads %d",
				(unsigned) h->format, CRAF_FORMAT);
	if (h->format != CRAF_FORMAT)
		return craf_err(CRAF_REFUSED, "unsupported version %u",
				(unsigned) h->format);
	h->hdr_len = b->data[10] | b->data[11] << 8;
	if (h->hdr_len < CRAF_PREFIX_LEN)
		return craf_err(CRAF_REFUSED, "inconsistent hdr_len %u",
				(unsigned) h->hdr_len);
	status = read_exactly(in, b->data + CRAF_PREFIX_LEN,
			      h->hdr_len - CRAF_PREFIX_LEN);
	if (status)
		return status;
	b->len = h->hdr_len;

	r.data = b->data;
	r.len = b->len;
	r.pos = CRAF_PREFIX_LEN;
	if (!(craf_get_str(&r, "cipher_driver", h->cipher_driver) &&
	      craf_get_str(&r, "cipher_algo", h->cipher_algo) &&
	      craf_get_u8(&r, "key_len", &h->key_len) &&
	      craf_get_str(&r, "key_source", h->key_source) &&
	      craf_get_bytes(&r, "iv", h->iv, CRAF_IV_LEN)))
		return craf_err(CRAF_REFUSED, "header field \"%s\" %s",
				r.field, r.why);
	if (strcmp(h->cipher_algo, CRAF_CIPHER_ALGO) != 0)
		return craf_err(CRAF_REFUSED, "unsupported cipher_algo \"%s\"",
				h->cipher_algo);
	if (h->key_len != CRAF_KEY_LEN)
		return craf_err(CRAF_REFUSED, "unsupported key_len %u",
				(unsigned) h->key_len);
	/* Later steps add key sources to this same version */
	*src = craf_key_source_by_name(h->key_source);
	if (!*src)
		return craf_err(CRAF_FAILED,
				"unknown key_source \"%s\": a newer craf may read it",
				h->key_source);

	/* The fields of the key source end the header, exactly */
	status = (*src)->read_fields(&r, keys);
	if (status)
		return status;
	if (r.field)
		return craf_err(CRAF_REFUSED, "header field \"%s\" %s",
				r.field, r.why);
	if (r.pos != r.len)
		return craf_err(CRAF_REFUSED, "inconsistent hdr_len %u",
				(unsigned) h->hdr_len);
	return CRAF_OK;
}
