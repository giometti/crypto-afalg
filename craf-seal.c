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

#include <errno.h>
#include <string.h>
#include "craf-archive.h"
#include "craf-keys.h"

/* The header of the archive in hand */
static struct craf_wbuf hdr;

/*
 * The library's "no" is a driver the kernel does not have; a wrong usage
 * is the caller's, the lack of a driver for a key that needs one among
 * them; anything else could not be done. Unsealing through keycrypt, as
 * <name> says, with a key that is none was given the wrong key, whatever
 * -backend says: could not.
 */
static int open_cipher(const char *cmd, const char *driver,
		       const char *name, const struct kc_key *key,
		       int encrypt, const uint8_t *iv, enum kc_backend_sel sel,
		       const struct craf_driver_opts *drv,
		       struct kc_cipher **c)
{
	struct kc_error e;
	int status;

	status = kc_cipher_open_backend(c, sel, driver, key, encrypt, iv,
					CRAF_IV_LEN, drv->min_tier, &e);
	if (status == KC_REFUSED)
		return craf_err(CRAF_FAILED,
				"cipher_driver \"%s\" not available: %s", driver,
				strerror(e.errnum));
	if (status == KC_USAGE && e.errnum == EDESTADDRREQ)
		return craf_err(CRAF_USAGE,
				"%s: -cipher-driver or -cipher-algo is required",
				cmd);
	if (status == KC_USAGE && e.errnum == EOPNOTSUPP && !encrypt)
		return craf_err(CRAF_FAILED, "%s: %s needs a keycrypt key: %s",
				cmd, name, e.msg);
	if (status == KC_USAGE)
		return craf_err(CRAF_USAGE, "%s: %s", cmd, e.msg);
	if (status && driver)
		return craf_err(CRAF_FAILED, "cannot open \"%s\": %s", driver,
				e.msg);
	if (status)
		return craf_err(CRAF_FAILED, "cannot open the cipher: %s",
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
	struct craf_key_opts o = *opts;
	const struct craf_key_source *src;
	struct craf_keys keys = {};
	struct craf_header h = {};
	struct kc_cipher *c = NULL;
	struct kc_error e;
	char driver[CRAF_STR_MAX + 1];
	uint8_t plain[CRAF_BUF_SIZE];
	uint8_t cipher[CRAF_BUF_SIZE + CRAF_BLOCK];
	size_t n, len;
	int status;

	status = craf_seal_source(opts, &src);
	if (status)
		return status;
	o.keycrypt = drv->backend == KC_BACKEND_KEYCRYPT;
	status = src->seal_keys(&o, &keys);
	if (status)
		goto out;
	if (drv->cipher_driver || drv->cipher_algo) {
		status = seal_driver(drv, driver);
		if (status)
			goto out;
	}

	/*
	 * The library draws the IV, and says what runs the cipher: the
	 * driver, or keycrypt@<backend> for a keycrypt key, which takes no
	 * driver and needs one in the header all the same
	 */
	status = open_cipher("seal", drv->cipher_driver || drv->cipher_algo ?
			     driver : NULL, NULL, keys.enc, 1, NULL,
			     drv->backend, drv, &c);
	if (status)
		goto out;
	if (kc_cipher_iv(c, h.iv, sizeof(h.iv), &e)) {
		status = craf_err(CRAF_FAILED, "%s", e.msg);
		goto out;
	}
	strcpy(h.cipher_driver, kc_cipher_driver(c));
	strcpy(h.cipher_algo, CRAF_CIPHER_ALGO);
	h.key_len = CRAF_KEY_LEN;
	status = craf_header_write(&hdr, &h, src, &keys);
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
	struct craf_key_opts o = *opts;
	const struct craf_key_source *src = NULL;
	struct craf_keys keys = {};
	struct craf_header h = {};
	struct kc_cipher *c = NULL;
	struct kc_error e;
	char driver[CRAF_STR_MAX + 1];
	const char *name;
	bool keycrypt;
	uint8_t buf[CRAF_BUF_SIZE];
	uint8_t plain[CRAF_BUF_SIZE + CRAF_BLOCK];
	size_t n, len;
	int status;

	/* The whole header, its driver included, before the keyring */
	status = craf_header_read(in, &hdr, &h, &src, &keys);
	if (!status)
		status = craf_unseal_key_opts(src, opts);
	if (status)
		goto out;

	/*
	 * The driver says the backend, the header's or the one given: a
	 * keycrypt key runs on the backend that holds it, which the kernel
	 * names once the key is open; any other driver as for AF_ALG
	 */
	name = drv->cipher_driver ? drv->cipher_driver : h.cipher_driver;
	keycrypt = strncmp(name, KC_KEYCRYPT_DRIVER_PREFIX,
			   strlen(KC_KEYCRYPT_DRIVER_PREFIX)) == 0;
	if (keycrypt && drv->any_driver)
		status = craf_err(CRAF_USAGE, "unseal: -any-driver chooses a "
				  "driver of AF_ALG, and the archive is of %s",
				  name);
	else if (keycrypt && drv->backend == KC_BACKEND_AFALG)
		status = craf_err(CRAF_USAGE, "unseal: -backend afalg, and the "
				  "archive is of %s", name);
	else if (!keycrypt && drv->backend == KC_BACKEND_KEYCRYPT)
		status = craf_err(CRAF_USAGE, "unseal: -backend keycrypt, and the "
				  "archive is of %s", name);
	else if (!keycrypt)
		status = unseal_driver(drv, &h, driver);
	o.keycrypt = keycrypt;
	if (!status)
		status = src->unseal_keys(&o, &keys);
	if (!status)
		status = open_cipher("unseal", keycrypt ? NULL : driver, name,
				     keys.enc, 0, h.iv, keycrypt ?
				     KC_BACKEND_KEYCRYPT : KC_BACKEND_AFALG,
				     drv, &c);
	if (!status && keycrypt && strcmp(kc_cipher_driver(c), name) != 0)
		status = craf_err(CRAF_FAILED, "unseal: the archive is of %s, "
				  "the key is run by %s: -cipher-driver %s to "
				  "unseal it with this key", name,
				  kc_cipher_driver(c), kc_cipher_driver(c));
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

	/*
	 * A wrong length still gives the last whole block, which goes out
	 * before the refusal; the refusal is then the exit status.
	 */
	if (kc_cipher_final(c, plain, &len, &e)) {
		write_output(out, plain, len);	/* intentionally ignored */
		status = cipher_err(&e);
	} else
		status = write_output(out, plain, len);
out:
	kc_cipher_free(c);
	if (src)
		craf_release_keys(src, &keys);
	return status;
}
