/*
 * craf-seal.c - craf seal and unseal: the streams through libkcrypto
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
#include <sys/random.h>
#include "craf-archive.h"
#include "craf-keys.h"

/* The header of the archive in hand */
static struct craf_wbuf hdr;

/*
 * The library's "no" is a bad decrypt, or a driver the kernel does not
 * have; anything else could not be done
 */
static int open_cipher(const char *driver, const struct kc_key *key,
		       int encrypt, const uint8_t *iv, struct kc_cipher **c)
{
	struct kc_error e;
	int status;

	status = kc_cipher_open(c, driver, key, encrypt, iv, CRAF_IV_LEN, &e);
	if (status == KC_REFUSED)
		return craf_err(CRAF_FAILED,
				"cipher_driver \"%s\" not available: %s", driver,
				strerror(e.errnum));
	if (status)
		return craf_err(CRAF_FAILED, "cannot open \"%s\": %s", driver,
				e.msg);
	return CRAF_OK;
}

static int cipher_err(const struct kc_error *e)
{
	return craf_err(e->status == KC_REFUSED ? CRAF_REFUSED : CRAF_FAILED,
			"%s", e->msg);
}

static int read_input(FILE *in, uint8_t *p, size_t size, size_t *n)
{
	*n = fread(p, 1, size, in);
	if (*n < size && ferror(in))
		return craf_err(CRAF_FAILED, "cannot read input: %m");
	return CRAF_OK;
}

static int write_output(FILE *out, const uint8_t *p, size_t len)
{
	if (len > 0 && fwrite(p, 1, len, out) != len)
		return craf_err(CRAF_FAILED, "cannot write output: %m");
	return CRAF_OK;
}

/* A driver of another algorithm is a wrong -cipher-driver */
static int seal_driver(const struct craf_driver_opts *drv, char *driver)
{
	int status;

	if (drv->cipher_algo)
		return craf_driver_for_algo(drv->cipher_algo, driver);
	status = craf_driver_check("-cipher-driver", drv->cipher_driver,
				   CRAF_CIPHER_ALGO, CRAF_USAGE);
	if (!status)
		strcpy(driver, drv->cipher_driver);
	return status;
}

/*
 * The header's driver is bound only if the kernel already lists it as
 * one of the header's algorithm: an archive chooses nothing the kernel
 * would build. Not listed, it could not be used; listed for another
 * algorithm, the header is false. -cipher-driver and -any-driver
 * replace it.
 */
static int unseal_driver(const struct craf_driver_opts *drv,
			 const struct craf_header *h, char *driver)
{
	const char *name = h->cipher_driver;
	int status;

	if (drv->any_driver)
		return craf_driver_for_algo(h->cipher_algo, driver);
	if (drv->cipher_driver) {
		name = drv->cipher_driver;
		status = craf_driver_check("-cipher-driver", name,
					   h->cipher_algo, CRAF_USAGE);
	} else
		status = craf_driver_listed("cipher_driver", name,
					    h->cipher_algo, CRAF_REFUSED,
					    false);
	if (!status)
		strcpy(driver, name);
	return status;
}

int craf_seal(FILE *in, FILE *out, const struct craf_driver_opts *drv,
	      const struct craf_key_opts *opts)
{
	const struct craf_key_source *src;
	struct craf_keys keys = {};
	struct craf_header h = {};
	struct kc_cipher *c = NULL;
	struct kc_error e;
	uint8_t plain[CRAF_BUF_SIZE];
	uint8_t cipher[CRAF_BUF_SIZE + CRAF_BLOCK];
	size_t n, len;
	int status;

	status = craf_seal_source(opts, &src);
	if (status)
		return status;
	status = src->seal_keys(opts, &keys);
	if (status)
		goto out;
	status = seal_driver(drv, h.cipher_driver);
	if (status)
		goto out;

	if (getrandom(h.iv, CRAF_IV_LEN, 0) != CRAF_IV_LEN) {
		status = craf_err(CRAF_FAILED, "cannot get a random IV: %m");
		goto out;
	}
	strcpy(h.cipher_algo, CRAF_CIPHER_ALGO);
	h.key_len = CRAF_KEY_LEN;
	status = craf_header_write(&hdr, &h, src, &keys);
	if (status)
		goto out;
	status = open_cipher(h.cipher_driver, keys.enc, 1, h.iv, &c);
	if (!status)
		status = write_output(out, hdr.data, hdr.len);
	if (status)
		goto out;

	do {
		status = read_input(in, plain, sizeof(plain), &n);
		if (status)
			goto out;
		if (kc_cipher_update(c, plain, n, cipher, &len, &e)) {
			status = cipher_err(&e);
			goto out;
		}
		status = write_output(out, cipher, len);
		if (status)
			goto out;
	} while (n > 0);

	/* The last block, with the PKCS#7 padding */
	if (kc_cipher_final(c, cipher, &len, &e))
		status = cipher_err(&e);
	else
		status = write_output(out, cipher, len);
out:
	kc_cipher_free(c);
	craf_release_keys(src, &keys);
	return status;
}

int craf_unseal(FILE *in, FILE *out, const struct craf_driver_opts *drv,
		const struct craf_key_opts *opts)
{
	const struct craf_key_source *src = NULL;
	struct craf_keys keys = {};
	struct craf_header h = {};
	struct kc_cipher *c = NULL;
	struct kc_error e;
	char driver[CRAF_STR_MAX + 1];
	uint8_t buf[CRAF_BUF_SIZE];
	uint8_t plain[CRAF_BUF_SIZE + CRAF_BLOCK];
	size_t n, len;
	int status;

	/* The whole header, its driver included, before the keyring */
	status = craf_header_read(in, &hdr, &h, &src, &keys);
	if (!status)
		status = craf_unseal_key_opts(src, opts);
	if (!status)
		status = unseal_driver(drv, &h, driver);
	if (!status)
		status = src->unseal_keys(opts, &keys);
	if (!status)
		status = open_cipher(driver, keys.enc, 0, h.iv, &c);
	if (status)
		goto out;

	/*
	 * The library holds back the last block, which may hold the
	 * padding: it goes out at the end, without the padding.
	 */
	do {
		status = read_input(in, buf, sizeof(buf), &n);
		if (status)
			goto out;
		if (kc_cipher_update(c, buf, n, plain, &len, &e)) {
			status = cipher_err(&e);
			goto out;
		}
		status = write_output(out, plain, len);
		if (status)
			goto out;
	} while (n > 0);

	if (kc_cipher_final(c, plain, &len, &e))
		status = cipher_err(&e);
	else
		status = write_output(out, plain, len);
out:
	kc_cipher_free(c);
	if (src)
		craf_release_keys(src, &keys);
	return status;
}
