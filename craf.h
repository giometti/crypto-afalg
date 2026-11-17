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
	enum kc_backend_sel backend;	/* -backend, KC_BACKEND_AUTO if not */
	unsigned int min_tier;		/* -enc-min-tier, 0 if not given */
	bool backend_opts;		/* either of the two given */
};

struct craf_key_opts;

/* Where the passphrase of enc comes from: the last option given says */
enum craf_pass_from {
	CRAF_PASS_NONE,
	CRAF_PASS_KFILE,		/* -kfile */
	CRAF_PASS_TEXT,			/* -k */
	CRAF_PASS_SPEC,			/* -pass */
};

/* What the command line says to enc */
struct craf_enc_opts {
	bool help;
	bool decrypt;			/* -d, with no -e after it */
	const char *in;
	const char *out;
	const char *openssl_name;	/* -<cipher>, without the dash */
	const char *cipher_algo;	/* -cipher-algo */
	long cipher_key_len;		/* -cipher-key-len, 0 if not given */
	const char *cipher_driver;	/* -cipher-driver */
	char kname[CRAF_STR_MAX + 1];	/* the cipher as the kernel names it */
	size_t key_len;			/* 0: the only one the kernel takes */
	bool pbkdf2;
	long iter;			/* 0: openssl's default */
	const char *md;
	bool md_given;			/* -md, against -enc-key */
	enum craf_pass_from pass_from;
	const char *pass;		/* the file, the text or the source */
	int pass_fd;			/* of -pass fd:, -1 for none */
	const char *enc_key;		/* -enc-key, in place of a passphrase */
	const char *iv;			/* -iv, in hex, with -enc-key */
	enum kc_backend_sel backend;	/* -backend, KC_BACKEND_AUTO if not */
	unsigned int min_tier;		/* -enc-min-tier, 0 if not given */
	bool backend_opts;		/* either given, not for a passphrase */
};

/* What the command line says to dgst */
struct craf_dgst_opts {
	bool help;
	const char *hash;		/* -<hash>, without the dash */
	const char *digest_algo;	/* -digest-algo */
	char kname[KC_NAME_MAX + 1];	/* the hash as the kernel names it */
	const char *label;		/* that of an exception, or NULL */
	bool binary;			/* -binary, -hex the last given */
	const char *keyform;		/* -keyform, PEM or DER */
	const char *verify;		/* -verify, the file of a public key */
	const char *verify_key;		/* -verify-key, a key of the keyring */
	const char *signature;		/* -signature */
	char **files;
	int nfiles;
};

/* A file of key material, read after the output is truncated */
struct craf_key_file {
	const char *what;		/* the option that names it */
	const char *path;		/* NULL, or */
	int fd;				/* a descriptor, -1 for none */
};

extern int craf_driver_listed(const char *what, const char *driver,
			      const char *algo, int mismatch, bool user);
extern int craf_driver_check(const char *what, const char *driver,
			     const char *algo, int mismatch);
extern int craf_driver_for_algo(const char *algo, char *driver);

extern int craf_check_driver_name(const char *name);
extern int craf_parse_backend(const char *arg, enum kc_backend_sel *sel);
extern int craf_parse_tier(const char *arg, unsigned int *tier);
extern int craf_check_algo_name(const char *cmd, const char *type,
				const char *opt, const char *name,
				const char *driver_opt);

struct option;
extern bool craf_typed_exactly(const char *arg, const char *name);
extern bool craf_exact_option(const struct option *options, const char *arg);

extern int craf_enc_parse(int argc, char *argv[], struct craf_enc_opts *o);
extern void craf_enc_key_file(const struct craf_enc_opts *o,
			      struct craf_key_file *kf);
extern int craf_enc(FILE *in, FILE *out, struct craf_enc_opts *o);

extern int craf_dgst_parse(int argc, char *argv[], struct craf_dgst_opts *o);
extern int craf_dgst(const struct craf_dgst_opts *o);

extern int craf_seal(FILE *in, FILE *out, const struct craf_driver_opts *drv,
		     const struct craf_key_opts *keys);
extern int craf_unseal(FILE *in, FILE *out,
		       const struct craf_driver_opts *drv,
		       const struct craf_key_opts *keys);
extern int craf_info(FILE *in, FILE *out);

#endif /* CRAF_H */
