/*
 * craf.h - single-file encrypted archives over AF_ALG
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

#ifndef CRAF_H
#define CRAF_H

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "afalg.h"
#include "kcrypto.h"
#include "misc.h"

/* Exit statuses */
#define CRAF_OK			0
#define CRAF_REFUSED		1	/* format, truncation, bad decrypt */
#define CRAF_USAGE		2
#define CRAF_FAILED		3	/* driver, key, /proc/crypto, I/O */

/* The archive format, version 1 */
#define CRAF_MAGIC		"AFALGARC"
#define CRAF_MAGIC_LEN		8
#define CRAF_FORMAT		1
#define CRAF_PREFIX_LEN		12	/* magic, version, hdr_len */
#define CRAF_CIPHER_ALGO	"cbc(aes)"
#define CRAF_KEY_LEN		32
#define CRAF_IV_LEN		16
#define CRAF_BLOCK		16
#define CRAF_STR_MAX		255

#define CRAF_BUF_SIZE		8192	/* a multiple of CRAF_BLOCK */

/* Report an error, giving the exit status it ends with */
#define craf_err(status, fmt, args...)					\
	({								\
		err(fmt, ## args);					\
		(status);						\
	})

/* What the command line says of the driver */
struct craf_driver_opts {
	const char *cipher_driver;	/* seal -cipher-driver */
	const char *cipher_algo;	/* seal -cipher-algo */
	bool any_driver;		/* unseal -any-driver */
};

struct craf_key_opts;

extern int craf_driver_listed(const char *what, const char *driver,
			      const char *algo, int mismatch, bool user);
extern int craf_driver_check(const char *what, const char *driver,
			     const char *algo, int mismatch);
extern int craf_driver_for_algo(const char *algo, char *driver);

extern int craf_seal(FILE *in, FILE *out, const struct craf_driver_opts *drv,
		     const struct craf_key_opts *keys);
extern int craf_unseal(FILE *in, FILE *out,
		       const struct craf_driver_opts *drv,
		       const struct craf_key_opts *keys);

#endif /* CRAF_H */
