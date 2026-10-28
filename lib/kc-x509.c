/*
 * kc-x509.c - the certificate the kernel loads around a public key
 *	       (libkcrypto)
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

/* No public key is this long: an RSA key of 16384 bits takes about 2100 */
#define SPKI_MAX		16384

/* The length of the signature, whose bytes are all zero */
#define SIG_LEN			256

/*
 * What the certificate holds before the public key, in DER: the serial
 * number 1, the signature algorithm, the issuer, the validity and the
 * subject. The issuer differs from the subject, so the certificate is not
 * self-signed and the kernel does not check its signature, which is no
 * signature. The validity is the widest X.509 has, 1970 to 9999, since a
 * board may boot with its clock anywhere.
 */
static const char tbs_head[] =
	"\x02\x01\x01"
	"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"
	"\x30\x19\x31\x17\x30\x15\x06\x03\x55\x04\x03\x0c\x0e"
	"kcrypto issuer"
	"\x30\x20\x17\x0d" "700101000000Z" "\x18\x0f" "99991231235959Z"
	"\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x03\x0c\x07"
	"kcrypto";

/* sha256WithRSAEncryption, which the kernel wants the same in both places */
static const char sig_algo[] =
	"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00";

/* The length of the DER header of content len bytes long */
static size_t der_head_len(size_t len)
{
	size_t n = 0;

	if (len < 0x80)
		return 2;
	while (len >> (8 * n))
		n++;
	return 2 + n;
}

static unsigned char *der_head(unsigned char *p, unsigned char tag,
			       size_t len)
{
	size_t n = der_head_len(len) - 2;

	*p++ = tag;
	if (n == 0) {
		*p++ = len;
		return p;
	}
	*p++ = 0x80 | n;
	while (n-- > 0)
		*p++ = len >> (8 * n);
	return p;
}

/*
 * Whether p is one DER SEQUENCE len bytes long, with a length of at most
 * two bytes, in its shortest form as DER wants it
 */
static bool one_sequence(const unsigned char *p, size_t len)
{
	size_t body;

	if (len < 2 || p[0] != 0x30)
		return false;
	if (p[1] < 0x80)
		return (size_t) p[1] + 2 == len;
	if (p[1] == 0x81)
		return len >= 3 && p[2] >= 0x80 && (size_t) p[2] + 3 == len;
	if (p[1] == 0x82) {
		if (len < 4)
			return false;
		body = (size_t) p[2] << 8 | p[3];
		return body >= 0x100 && body + 4 == len;
	}
	return false;
}

int kc_x509_wrap(const void *spki, size_t len, unsigned char **der,
		 size_t *der_len, struct kc_error *e)
{
	size_t head = sizeof(tbs_head) - 1, algo = sizeof(sig_algo) - 1;
	size_t tbs, sig, body;
	unsigned char *p;

	*der = NULL;
	if (len > SPKI_MAX)
		return kc_fail(e, KC_USAGE, E2BIG, "public key too long");
	if (!one_sequence(spki, len))
		return kc_fail(e, KC_USAGE, EINVAL,
			       "the public key is not one DER SEQUENCE of %zu "
			       "bytes", len);

	tbs = head + len;
	sig = 1 + SIG_LEN;
	body = der_head_len(tbs) + tbs + algo + der_head_len(sig) + sig;
	*der_len = der_head_len(body) + body;
	p = *der = malloc(*der_len);
	if (!p)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));

	p = der_head(p, 0x30, body);
	p = der_head(p, 0x30, tbs);
	memcpy(p, tbs_head, head);
	p += head;
	memcpy(p, spki, len);
	p += len;
	memcpy(p, sig_algo, algo);
	p += algo;
	p = der_head(p, 0x03, sig);
	memset(p, 0, sig);	/* no unused bits, then the signature */
	return kc_ok(e);
}
