/*
 * craf-seal.c - craf seal and unseal: the streams through AF_ALG
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

/* The socket of one operation of <driver>, with <key>, <op> and <iv> */
static int open_cipher(const char *driver, const struct afalg_key *key,
		       int op, const uint8_t *iv, int *fd)
{
	int s;

	s = afalg_socket();
	if (s < 0)
		return craf_err(CRAF_FAILED, "socket(AF_ALG): %m");
	if (afalg_bind(s, "skcipher", driver) < 0) {
		err("cipher_driver \"%s\" not available: %m", driver);
		close(s);
		return CRAF_FAILED;
	}
	if (afalg_set_key(s, key) < 0) {
		err("cannot set the key of \"%s\": %m", driver);
		close(s);
		return CRAF_FAILED;
	}
	*fd = afalg_accept(s);
	close(s);		/* the operation keeps the transform */
	if (*fd < 0)
		return craf_err(CRAF_FAILED, "cannot open \"%s\": %m", driver);
	if (afalg_set_op_iv(*fd, op, iv, CRAF_IV_LEN) < 0)
		return craf_err(CRAF_FAILED, "cannot set the IV of \"%s\": %m",
				driver);
	return CRAF_OK;
}

static int process(int fd, const uint8_t *in, uint8_t *out, size_t len)
{
	ssize_t n;

	n = afalg_send(fd, in, len);
	if (n < 0)
		return craf_err(CRAF_FAILED, "cannot send data to the kernel: %m");
	if ((size_t) n != len)
		return craf_err(CRAF_FAILED, "the kernel took %zd of %zu bytes",
				n, len);
	n = afalg_recv(fd, out, len);
	if (n < 0)
		return craf_err(CRAF_FAILED,
				"cannot read data from the kernel: %m");
	if ((size_t) n != len)
		return craf_err(CRAF_FAILED, "the kernel gave %zd of %zu bytes",
				n, len);
	return CRAF_OK;
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
	uint8_t plain[CRAF_BUF_SIZE + CRAF_BLOCK];
	uint8_t cipher[CRAF_BUF_SIZE + CRAF_BLOCK];
	size_t carry = 0, n, len, pad;
	int enc = -1, status;

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
	status = open_cipher(h.cipher_driver, &keys.enc, ALG_OP_ENCRYPT, h.iv,
			     &enc);
	if (!status)
		status = write_output(out, hdr.data, hdr.len);
	if (status)
		goto out;

	/* Whole blocks go out as they come, the rest waits for more */
	do {
		status = read_input(in, plain + carry, CRAF_BUF_SIZE, &n);
		if (status)
			goto out;
		len = carry + n;
		carry = len % CRAF_BLOCK;
		len -= carry;
		if (len == 0)
			continue;
		status = process(enc, plain, cipher, len);
		if (!status)
			status = write_output(out, cipher, len);
		if (status)
			goto out;
		memmove(plain, plain + len, carry);
	} while (n > 0);

	/* PKCS#7: 1 to CRAF_BLOCK bytes, each holding their count */
	pad = CRAF_BLOCK - carry;
	memset(plain + carry, pad, pad);
	status = process(enc, plain, cipher, CRAF_BLOCK);
	if (!status)
		status = write_output(out, cipher, CRAF_BLOCK);
out:
	if (enc >= 0)
		close(enc);
	src->release(&keys);
	return status;
}

int craf_unseal(FILE *in, FILE *out, const struct craf_driver_opts *drv,
		const struct craf_key_opts *opts)
{
	const struct craf_key_source *src = NULL;
	struct craf_keys keys = {};
	struct craf_header h = {};
	char driver[CRAF_STR_MAX + 1];
	uint8_t buf[CRAF_BUF_SIZE + CRAF_BLOCK];
	uint8_t plain[CRAF_BUF_SIZE + CRAF_BLOCK];
	uint8_t held[CRAF_BLOCK];
	size_t have = 0, n, take, pad, i;
	bool holding = false;
	uint8_t diff;
	int enc = -1, status;

	/* The whole header, its driver included, before the keyring */
	status = craf_header_read(in, &hdr, &h, &src, &keys);
	if (!status)
		status = craf_unseal_key_opts(src, opts);
	if (!status)
		status = unseal_driver(drv, &h, driver);
	if (!status)
		status = src->unseal_keys(opts, &keys);
	if (!status)
		status = open_cipher(driver, &keys.enc, ALG_OP_DECRYPT, h.iv,
				     &enc);
	if (status)
		goto out;

	/*
	 * The last block decrypted may hold the padding: it goes out only
	 * once another one follows, or at the end, without the padding.
	 */
	do {
		status = read_input(in, buf + have, CRAF_BUF_SIZE, &n);
		if (status)
			goto out;
		have += n;
		take = have - have % CRAF_BLOCK;
		if (take == 0)
			continue;
		status = process(enc, buf, plain, take);
		if (!status && holding)
			status = write_output(out, held, CRAF_BLOCK);
		if (!status)
			status = write_output(out, plain, take - CRAF_BLOCK);
		if (status)
			goto out;
		memcpy(held, plain + take - CRAF_BLOCK, CRAF_BLOCK);
		holding = true;
		have -= take;
		memmove(buf, buf + take, have);
	} while (n > 0);

	if (!holding || have != 0) {
		status = craf_err(CRAF_REFUSED,
				  "bad decrypt (wrong final block length)");
		goto out;
	}

	/* PKCS#7, as crypto-afalg and openssl check it */
	pad = held[CRAF_BLOCK - 1];
	diff = pad == 0 || pad > CRAF_BLOCK;
	for (i = CRAF_BLOCK - (diff ? 0 : pad); i < CRAF_BLOCK; i++)
		diff |= held[i] ^ pad;
	if (diff) {
		status = craf_err(CRAF_REFUSED, "bad decrypt (wrong padding)");
		goto out;
	}
	status = write_output(out, held, CRAF_BLOCK - pad);
out:
	if (enc >= 0)
		close(enc);
	if (src)
		src->release(&keys);
	return status;
}
