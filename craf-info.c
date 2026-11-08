/*
 * craf-info.c - craf info: the header of an archive, without decrypting
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

#include "craf-archive.h"
#include "craf-keys.h"

/* The header of the archive in hand */
static struct craf_wbuf hdr;

/*
 * The checks of unseal on the header, and nothing else: no key, no
 * /proc/crypto, no byte past the header. A header that fails them prints
 * nothing.
 */
int craf_info(FILE *in, FILE *out)
{
	const struct craf_key_source *src = NULL;
	struct craf_keys keys = {};
	struct craf_header h = {};
	size_t i;
	int status;

	status = craf_header_read(in, &hdr, &h, &src, &keys);
	if (!status) {
		fprintf(out, "version: %u\n", (unsigned) h.format);
		fprintf(out, "hdr_len: %u\n", (unsigned) h.hdr_len);
		fprintf(out, "cipher_driver: %s\n", h.cipher_driver);
		fprintf(out, "cipher_algo: %s\n", h.cipher_algo);
		fprintf(out, "key_len: %u\n", (unsigned) h.key_len);
		fprintf(out, "key_source: %s\n", h.key_source);
		fprintf(out, "iv: ");
		for (i = 0; i < CRAF_IV_LEN; i++)
			fprintf(out, "%02x", h.iv[i]);
		fprintf(out, "\n");
		src->print_fields(out, &keys);
	}
	if (src)
		craf_release_keys(src, &keys);
	return status;
}
