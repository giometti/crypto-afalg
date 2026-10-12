/*
 * crypto-hash.c - Simple AF_ALG implementation for Linux (hash)
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

#include <arpa/inet.h>
#include "crypto-afalg.h"

/*
 * Global variables & definitions
 */

#define MAX_DIGEST_SIZE		64
#define MAX_KEY_LEN             64

/*
 * Functions
 */

static int list_hashes(void)
{
	int algo;

	info("  name                kernel-name    block(B)   key(B)");
	for (algo = 0; algo < __AFALG_ALGO_END; algo++) {
		if (algo_type(algo) != AFALG_TYPE_HASH)
			continue;
		info("%c %-20s%-16s  %lu        %lu",
			is_in_proc_crypto("hash",
					algo_kname(algo), NULL) ?  '-' : 'x',
			algo_name(algo), algo_kname(algo),
			algo_block_size(algo), algo_key_len(algo));
	}
	info("  NOTE: 'x' means 'not available'");
	info("  NOTE: algo with key(B) > 0 requires a key");

	exit(EXIT_SUCCESS);
	return 0;
}

static bool check_hash(const char *kname)
{
	int algo;

	for (algo = 0; algo < __AFALG_ALGO_END; algo++) {
		if (algo_type(algo) != AFALG_TYPE_HASH)
			continue;
		if (strcmp(algo_kname(algo), kname))
			continue;
		if (is_in_proc_crypto("hash", kname, NULL))
			return true;
	}

	return false;
}

static enum afalg_algo_e parse_algo_hash(const char *str)
{
	int i;

	for (i = 0; i < __AFALG_ALGO_END; i++)
		if ((algo_type(i) == AFALG_TYPE_HASH) &&
		    (strcmp(algo_name(i), str) == 0))
			return i;

	fatal("invalid algo \"%s\"", str);
}

static size_t read_data(size_t block_size, char *ibuf)
{
	size_t size;

	size = fread(ibuf, 1, BUF_SIZE, stdin);
	/* A short read is the end of the input only if it is not an error */
	if (size < BUF_SIZE && ferror(stdin))
		fatal("cannot read input: %m");
	if (size > 0)
		return size;
	return 0;
}

static void process_data(int fd, char *ibuf, size_t size)
{
	int ret;

	ret = afalg_send(fd, ibuf, size);
       	if (ret < size) {
		if (ret < 0)
               		fatal("sendmsg(): %m");
		else
			fatal("too few data sent to the kernel!");
       	}
}

static void read_hash(int fd, char *buf, size_t size)
{
	int ret;

	ret = afalg_recv(fd, buf, size);
       	if (ret < size) {
		if (ret < 0)
               		fatal("read(): %m");
		else
			fatal("too few data received from the kernel!");
       	}
}

static void __hash_buffer(int s, char buf[], size_t len,
                char hash[], size_t hash_len)
{
	int fd = __get_afalg_socket(s);

        process_data(fd, buf, len);
        read_hash(fd, hash, hash_len);
	close(fd);
}

/*
 * The whole file is the key, newlines included: read it up to its end
 * with no fixed limit and without fsize(), since it may be a pipe
 */
static char *read_pass_alloc(const char *file, size_t *len)
{
	FILE *f;
	char *buf = NULL, *p;
	size_t size = 0, n;

	f = fopen(file, "r");
	if (!f)
		fatal("cannot open pass file %s: %m", file);
	*len = 0;
	do {
		if (*len == size) {
			size += BUF_SIZE;
			p = realloc(buf, size);
			if (!p)
				fatal("cannot allocate memory for pass file %s",
					file);
			buf = p;
		}
		n = fread(buf + *len, 1, size - *len, f);
		*len += n;
	} while (n > 0);
	if (ferror(f))
		fatal("cannot read pass file %s", file);
	if (*len == 0)
		fatal("pass file %s is empty", file);
	fclose(f);		/* intentionally ignored */

	return buf;
}

static void print_hash(uint8_t buf[], size_t size)
{
	char hex[2 * MAX_DIGEST_SIZE + 1];
	int i;

	for (i = 0; i < size; i++)
		sprintf(hex + 2 * i, "%02x", buf[i]);
	hex[2 * size] = '\n';
	write_output(hex, 2 * size + 1);
}

/*
 * Exported functions
 */
size_t hash_buffer(char buf[], size_t len,
		enum afalg_algo_e algo, char key[], size_t key_len,
		char hash[], size_t hash_len)
{
	struct afalg_key akey = {
		.type = AFALG_KEY_RAW,
		.raw = { .data = key, .len = key_len },
	};
	int fd = create_hash_socket(algo, &akey);

	process_data(fd, buf, len);
	read_hash(fd, hash, algo_digest_size(algo));
	close(fd);
	return algo_digest_size(algo);
}

int pbkdf2(char pass[], size_t pass_len, char salt[], size_t salt_len,
	   int iterations,
	   char key[], size_t key_len, char iv[], size_t iv_len)
{
	enum afalg_algo_e algo = AFALG_ALGO_HASH_HMAC_SHA256;
	char u[algo_key_len(algo)], t[algo_key_len(algo)];
	char salt_i[salt_len + 4];
	int current_len = 0;
	int block = 1;
	int cpy_len;
	int s, j, i;
	int derived_len = key_len + iv_len;
	char derived[derived_len];
	struct afalg_key akey = {
		.type = AFALG_KEY_RAW,
		.raw = { .data = pass, .len = pass_len },
	};

	/* Init the AF_ALG context for HMAC-SHA256 with a given pass key */
	s = __init_hash_socket(algo, &akey);

	memcpy(salt_i, salt, salt_len);
	while (current_len < derived_len) {
		/* Prepare the salt || block (big-endian) */
		uint32_t be_block = htonl(block);
		memcpy(salt_i + salt_len, &be_block, sizeof(be_block));

		/* Initial u is HMAC-SHA256(pass, salt || block) using
		 * an existing and already set up AF_ALG context.
		 */
		__hash_buffer(s, salt_i, salt_len + 4,
			u, algo_key_len(algo));

		memcpy(t, u, algo_key_len(algo));
		for (i = 1; i < iterations; i++) {
			/* perform the remaining iterations still using
			 * the already set up AF_ALG context.
			 */
			__hash_buffer(s, u, algo_key_len(algo),
				    u, algo_key_len(algo));

			/* XOR u into t */
			for (j = 0; j < algo_key_len(algo); j++)
				t[j] ^= u[j];
		}

		/* Copy the current block t to the final output */
		cpy_len = derived_len - current_len;
		if (cpy_len > algo_key_len(algo))
			cpy_len = algo_key_len(algo);
		memcpy(derived + current_len, t, cpy_len);
		current_len += cpy_len;
		block++;
	}

	/* Split the derived output into the key and IV */
	memcpy(key, derived, key_len);
	memcpy(iv, derived + key_len, iv_len);

	/* Now safely close the AF_ALG context */
	close(s);

	return 0;
}

/*
 * Crypt/Decrypt subcommands
 */

static void usage_hash(const char *cmd)
{
        fprintf(stderr,
		"to see available algos use:\n\t%s %s\n", NAME, cmd);
        fprintf(stderr,
		"to check a kernel algo use:\n\t%s %s check-kalgo <kname>\n",
							NAME, cmd);
        fprintf(stderr,
		"to get help use:\n\t%s %s help|-h|--help\n",
							NAME, cmd);
        fprintf(stderr,
                "normal usage:\n\t%s %s <algo> <KEY>\n", NAME, cmd);
        fprintf(stderr,
                "where <KEY> can be one of:\n"
                "    -K|--key <val>          : hex value key\n"
                "    -k|--keyfile <name>     : key from file\n"
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
                "    -S|--keyserial <val>    : key from keyring\n"
#endif
                "    -P|--pass <str>         : passkey\n"
                "    -p|--passfile <name>    : passkey from file\n");
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
        fprintf(stderr,
                "NOTE: keyring key can be:\n"
		"      - a simple serial number, or\n"
		"      - a symbolic name as [<keyring>,]<type>,<name>\n");
#endif
}

void do_hash(int argc, char *argv[])
{
        int opt;
        int long_index = 0;
        static struct option options[] = {
                { "help",	no_argument,		NULL, 'h' },
                { "key",        required_argument,      NULL, 'K' },
                { "keyfile",    required_argument,      NULL, 'k' },
                { "keyserial",  required_argument,      NULL, 'S' },
                { "pass",	required_argument,	NULL, 'P' },
                { "passfile",	required_argument,	NULL, 'p' },
                { 0, 0, 0, 0 }
        };
        int fd;
	enum afalg_algo_e algo;
        char keybuf[MAX_KEY_LEN], *key = keybuf, *keyalloc = NULL;
        size_t key_len = 0;
	bool key_given = false;
	struct afalg_key akey = { .type = AFALG_KEY_RAW };
	char ibuf[BUF_SIZE], obuf[MAX_DIGEST_SIZE];
	size_t nread;

	/* Check for common options */
        if (argc < 2) {
		list_hashes();
		exit(EXIT_SUCCESS);
	}
	if (strcmp("check-kalgo", argv[1]) == 0) {
		if (argc < 3)
			fatal("must specify a name");
		exit(check_hash(argv[2]) ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	if (strcmp("help", argv[1]) == 0 ||
	    strcmp("-h", argv[1]) == 0 ||
	    strcmp("--help", argv[1]) == 0) {
		usage_hash(argv[0]);
		exit(EXIT_SUCCESS);
	}

	/* Parse command line */
	algo = parse_algo_hash(argv[1]);
	BUG_ON(algo_key_len(algo) > MAX_KEY_LEN);

	optind = 0;
        while ((opt = getopt_long(argc, argv, "hK:k:S:P:p:", options,
                            &long_index)) >= 0) {
                switch (opt) {
                case 'h':
                        usage_hash(argv[0]);
                        exit(EXIT_SUCCESS);

		case 'K':
		case 'k':
		case 'S':
		case 'P':
		case 'p':
			if (algo_key_len(algo) == 0)
				fatal("%s takes no key", algo_name(algo));
			/* An empty passphrase is a key too */
			if (key_given)
				fatal("key already defined");
			key_given = true;
			key = keybuf;
			switch (opt) {
			case 'K':
				key_len = parse_key(optarg,
						key, algo_key_len(algo));
				break;
			case 'k':
				key_len = read_key(optarg,
						key, algo_key_len(algo));
				break;
			case 'S':
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
				num_key(optarg, &akey);
#else
				fatal("option -S|--keyserial unsupported");
#endif
				break;
			case 'P':
				key_len = str_key(optarg, &key);
				break;
			case 'p':
				keyalloc = read_pass_alloc(optarg, &key_len);
				key = keyalloc;
				break;
			}
			break;

                default:
                        fatal("wrong option! Use -h for help");
                }
        }
	if (algo_key_len(algo) > 0 && !key_given)
                fatal("no key defined!");
	if (akey.type == AFALG_KEY_RAW) {
		dbg_dump(key, key_len, "key:");
		akey.raw.data = key;
		akey.raw.len = key_len;
	}

	fd = create_hash_socket(algo, key_given ? &akey : NULL);

	BUG_ON(algo_digest_size(algo) > MAX_DIGEST_SIZE);
	do {
		nread = read_data(algo_block_size(algo), ibuf);
		if (nread == 0)
			break;

		process_data(fd, ibuf, nread);
	} while (nread > 0);

	read_hash(fd, obuf, algo_digest_size(algo));
	print_hash((uint8_t *) obuf, algo_digest_size(algo));
	flush_output();

	close(fd);
	free(keyalloc);
}
