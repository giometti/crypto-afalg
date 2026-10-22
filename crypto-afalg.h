/*
 * crypto-afalg.h - Simple AF_ALG implementation for Linux (header file)
 *
 * Copyright (C) 2025 Rodolfo Giometti <giometti@enneenne.com>
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

#ifndef CRYPTO_AFALG_H
#define CRYPTO_AFALG_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_alg.h>
#include <string.h>
#include "afalg.h"
#include "kcrypto.h"
#include "misc.h"

#define BUF_SIZE                PAGE_SIZE

/*
 * Algo data see /proc/crypto)
 */

enum afalg_type_e {
        AFALG_TYPE_CIPHER,
        AFALG_TYPE_HASH,
        __AFALG_TYPE_END
};

enum afalg_algo_e {
        AFALG_ALGO_CIPHER_AES128_CBC,
        AFALG_ALGO_CIPHER_AES256_CBC,
        AFALG_ALGO_CIPHER_AES256_CBC_CAAM,
        AFALG_ALGO_HASH_SHA256,
	AFALG_ALGO_HASH_HMAC_SHA256,
        __AFALG_ALGO_END
};

struct afalg_algo_data_s {
        char *name;
        char kname[64];
        size_t block_size;
	size_t key_len;
	enum afalg_type_e type;
	union {
		struct afalg_cipher {
			size_t iv_len;
		} cipher;
		struct afalg_hash {
			size_t digest_size;
		} hash;
	};
};
extern const struct afalg_algo_data_s afalg_algo_data[];

extern char *use_driver;

#define algo_name(algo)		afalg_algo_data[algo].name
#define algo_kname(algo)	afalg_algo_data[algo].kname
#define algo_block_size(algo)	afalg_algo_data[algo].block_size
#define algo_key_len(algo)	afalg_algo_data[algo].key_len
#define algo_type(algo)		afalg_algo_data[algo].type

#define algo_iv_len(algo)	afalg_algo_data[algo].cipher.iv_len

#define algo_digest_size(algo)	afalg_algo_data[algo].hash.digest_size

/* Common functions */
extern size_t fsize(FILE *f);
extern void write_output(const void *buf, size_t len);
extern void flush_output(void);
extern bool kernel_has_algo(const char *type, const char *name);
extern void check_driver(const char *type, enum afalg_algo_e algo);
extern size_t parse_str(const char *label,
                                const char *str, char *data, size_t len);
extern size_t parse_key(const char *str, char *key, size_t key_len);
extern size_t read_file(const char *label,
                                const char *file, char *data, size_t len);
extern size_t read_key(const char *file, char *key, size_t key_len);
extern void num_key(const char *str, struct afalg_key *key);
extern size_t str_key(char *str, char **key);

extern int __init_afalg_socket(const char *type, enum afalg_algo_e algo,
		const struct afalg_key *key);
extern int __get_afalg_socket(int s);
extern int create_afalg_socket(const char *type, enum afalg_algo_e algo,
		const struct afalg_key *key);
#define create_cipher_socket(algo, key) \
		create_afalg_socket("skcipher", algo, key)
#define __init_hash_socket(algo, key) \
		__init_afalg_socket("hash", algo, key)
#define create_hash_socket(algo, key) \
		create_afalg_socket("hash", algo, key)

/* Exported functions */
extern size_t hash_buffer(char buf[], size_t len,
		enum afalg_algo_e algo, char key[], size_t key_len,
		char hash[], size_t hash_len);
extern int pbkdf2(char pass[], size_t pass_len, char salt[], size_t salt_len,
		int iterations,
		char key[], size_t key_len, char iv[], size_t iv_len);

/* Crypto actions */
extern void do_crypt(int argc, char *argv[]);
extern void do_hash(int argc, char *argv[]);

#endif /* CRYPTO_AFALG_H */
