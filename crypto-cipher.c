/*
 * crypto-cipher.c - Simple AF_ALG implementation for Linux (skcipher)
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

#include <sys/random.h>
#include "crypto-afalg.h"

/*
 * Global variables & definitions
 */

#define MAX_BLOCK_SIZE		16
#define MAX_KEY_LEN		64
#define MAX_IV_LEN		32
#define SALT_LEN		8

static char padding[MAX_BLOCK_SIZE] = {
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
};
static char unwritten[MAX_BLOCK_SIZE];

/*
 * Functions
 */

static int list_ciphers(void)
{
	int algo;

	info("  name                kernel-name    block(B)   key/iv(B)");
	for (algo = 0; algo < __AFALG_ALGO_END; algo++) {
		if (algo_type(algo) != AFALG_TYPE_CIPHER)
			continue;
		info("%c %-20s%-16s  %lu        %lu/%lu",
			is_in_proc_crypto("skcipher",
					algo_kname(algo), NULL) ?  '-' : 'x',
			algo_name(algo), algo_kname(algo),
			algo_block_size(algo),
			algo_key_len(algo), algo_iv_len(algo));
	}
	info("  NOTE: 'x' means 'not available'");

	exit(EXIT_SUCCESS);
	return 0;
}

static bool check_cipher(const char *kname)
{
        int algo;

        for (algo = 0; algo < __AFALG_ALGO_END; algo++) {
                if (algo_type(algo) != AFALG_TYPE_CIPHER)
                        continue;
                if (strcmp(algo_kname(algo), kname))
                        continue;
                if (is_in_proc_crypto("skcipher", kname, NULL))
                        return true;
        }

        return false;
}

static enum afalg_algo_e parse_algo_cipher(const char *str)
{
	int i;

	for (i = 0; i < __AFALG_ALGO_END; i++)
		if ((algo_type(i) == AFALG_TYPE_CIPHER) &&
		    (strcmp(algo_name(i), str) == 0))
			return i;

	fatal("invalid algo \"%s\"", str);
}

static size_t parse_iv(const char *str, char *iv, size_t iv_len)
{
	return parse_str("iv", str, iv, iv_len);
}

static size_t read_iv(const char *file, char *iv, size_t iv_len)
{
	return read_file("iv", file, iv, iv_len);
}

static size_t parse_salt(const char *str, char *salt, size_t salt_len)
{
	return parse_str("salt", str, salt, salt_len);
}

static size_t read_salt(const char *file, char *salt, size_t salt_len)
{
	return read_file("salt", file, salt, salt_len);
}

static void init_afalg_data(int fd, int cmd, char *iv, size_t iv_len)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};
	struct af_alg_iv *iv_data;
	struct iovec iov;
	int ret;

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *) CMSG_DATA(cmsg) = cmd;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(20);
	iv_data = (void *) CMSG_DATA(cmsg);
	iv_data->ivlen = 16;
	memcpy(iv_data->iv, iv, iv_len);

	iov.iov_base = NULL;
	iov.iov_len = 0;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(fd, &msg, MSG_MORE);
        if (ret < 0)
                fatal("sendmsg(): %m");
}

static size_t detect_salt(char *salt)
{
	char marker[] = "Salted__";
	size_t size;

	size = fread(salt, 1, strlen(marker), stdin);
	if (size != strlen(marker))
		fatal("cannot read header");
	if (strcmp(marker, salt) != 0)
		return 0;
	size = fread(salt, 1, SALT_LEN, stdin);
	if (size != SALT_LEN)
		fatal("cannot read salt data");

	return SALT_LEN;
}

static size_t generate_salt(char *salt)
{
	return getrandom(salt, SALT_LEN, 0);
}

static size_t read_data(size_t block_size, char *ibuf, int cmd,
			size_t *last_size)
{
	size_t size;

	size = fread(ibuf, 1, BUF_SIZE, stdin);

	if (size > 0 || cmd == ALG_OP_DECRYPT) {
		*last_size = size;
		return size;
	}

	if (*last_size % block_size == 0) {
		memcpy(ibuf, padding, block_size);
		*last_size = block_size - 1;
		return block_size;
	}
	return 0;
}

static size_t pad_data(size_t block_size, char *buf, size_t size)
{
	size_t pad_size = block_size - size % block_size;

	if (pad_size == block_size)
		return size;

	memset(buf + size, pad_size, pad_size);
	return size + pad_size;
}

static void process_data(int fd, char *ibuf, char *obuf, size_t size)
{
	int ret;

	ret = send(fd, ibuf, size, MSG_MORE);
       	if (ret < size) {
		if (ret < 0)
               		fatal("sendmsg(): %m");
		else
			fatal("too few data sent to the kernel!");
       	}
	ret = read(fd, obuf, size);
       	if (ret < size) {
		if (ret < 0)
               		fatal("read(): %m");
		else
			fatal("too few data received from the kernel!");
       	}
}

static void write_salt(char *salt, size_t salt_len)
{
	char marker[] = "Salted__";
	size_t size;

	size = fwrite(marker, 1, strlen(marker), stdout);
	if (size != strlen(marker))
		fatal("cannot write header");
	size = fwrite(salt, 1, SALT_LEN, stdout);
	if (size != SALT_LEN)
		fatal("cannot write salt data");
}

static void write_data(size_t block_size, char *obuf, size_t size, int cmd,
			char unwritten[], size_t *last_unwritten)
{
	size_t n;

	if (cmd == ALG_OP_DECRYPT) {
		if (size > block_size) {
			if (*last_unwritten > 0)
				fwrite(unwritten, 1, *last_unwritten, stdout);
			memcpy(unwritten, obuf + size - block_size, block_size);
			size -= block_size;
			*last_unwritten = block_size;

			fwrite(obuf, 1, size, stdout);
		} else if (size == block_size) {
			fwrite(unwritten, 1, *last_unwritten, stdout);
			memcpy(unwritten, obuf, size);
			*last_unwritten = size;
		} else if (size == 0) {
			if (memcmp(unwritten, padding, block_size) == 0)
				return;
			n = unwritten[block_size - 1];
			if (n < 0x10 && unwritten[block_size - n] == n)
				n = block_size - n;
			else
				n = block_size;
			fwrite(unwritten, 1, n, stdout);
		} else
			BUG();
	} else
		fwrite(obuf, 1, size, stdout);
}

/*
 * Crypt/Decrypt subcommands
 */

static void usage_cipher(const char *cmd)
{
        fprintf(stderr,
		"to see available algos use:\n\t%s %s\n", NAME, cmd);
        fprintf(stderr,
		"to check a kernel algo use:\n\t%s %s check-kalgo <kname>\n",
							NAME, cmd);
        fprintf(stderr,
		"to get help use:           \n\t%s %s help|-h|--help\n",
							NAME, cmd);
        fprintf(stderr,
                "normal usage:\n\t%s %s <algo> <KEY> <IV> | "
		"<PASS> [ <SALT> ] [ -i|--iterations <val> ]\n", NAME, cmd);
        fprintf(stderr,
                "where <KEY> can be one of:\n"
                "    -K|--key <val>          : hex value key\n"
                "    -k|--keyfile <name>     : key from file\n"
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
                "    -S|--keyserial <val>    : key from keyring\n"
#endif
                "where <IV> can be one of:\n"
                "    -V|--iv <str>           : iv\n"
                "    -v|--ivfile <name>      : iv from file\n");
        fprintf(stderr,
                "where <PASS> can be one of:\n"
                "    -P|--pass <str>         : passkey\n"
                "    -p|--passfile <name>    : passkey from file\n"
                "where <SALT> can be one of:\n"
                "    -T|--salt <str>         : salt\n"
                "    -t|--saltfile <name>    : salt from file\n");
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
	fprintf(stderr,
		"NOTE: keyring key can be:\n"
		"      - a simple serial number, or\n"
		"      - a symbolic name as [<keyring>,]<type>,<name>\n");
#endif
}

void do_crypt(int argc, char *argv[])
{
        int opt;
        int long_index = 0;
        static struct option options[] = {
                { "help",	no_argument,		NULL, 'h' },
                { "key",	required_argument,	NULL, 'K' },
                { "keyfile",	required_argument,	NULL, 'k' },
                { "keyserial",	required_argument,	NULL, 'S' },
                { "iv",		required_argument,	NULL, 'V' },
                { "ivfile",	required_argument,	NULL, 'v' },
                { "pass",	required_argument,	NULL, 'P' },
                { "passfile",	required_argument,	NULL, 'p' },
                { "salt",	required_argument,	NULL, 'T' },
                { "saltfile",	required_argument,	NULL, 't' },
                { "iterations",	required_argument,	NULL, 'i' },
                { 0, 0, 0, 0 }
        };
        int op, fd;
	enum afalg_algo_e algo;
	char key[MAX_KEY_LEN], iv[MAX_IV_LEN];
	size_t key_len = 0, iv_len = 0;
	char pass[MAX_KEY_LEN], salt[SALT_LEN];
	size_t pass_len = 0, salt_len = 0;
	int iterations = 10000;	/* the default */
	bool generated_salt = false;
	char ibuf[BUF_SIZE], obuf[BUF_SIZE];
	size_t nread, last_nread, size, last_unwritten;

	/* Check for common options */
        if (argc < 2) {
		list_ciphers();
		exit(EXIT_SUCCESS);
	}
        if (strcmp("check-kalgo", argv[1]) == 0) {
                if (argc < 3)
                        fatal("must specify an name");
                exit(check_cipher(argv[2]) ? EXIT_SUCCESS : EXIT_FAILURE);
        }
	if (strcmp("help", argv[1]) == 0 ||
	    strcmp("-h", argv[1]) == 0 ||
	    strcmp("--help", argv[1]) == 0) {
		usage_cipher(argv[0]);
		exit(EXIT_SUCCESS);
	}

	/* Parse command line */
	op = argv[0][0] == 'e' ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
	algo = parse_algo_cipher(argv[1]);
	BUG_ON(algo_key_len(algo) > MAX_KEY_LEN);
	BUG_ON(algo_iv_len(algo) > MAX_IV_LEN);

	optind = 0;
        while ((opt = getopt_long(argc, argv, "hK:k:S:V:v:P:p:T:t:i:", options,
                            &long_index)) >= 0) {
                switch (opt) {
                case 'h':
                        usage_cipher(argv[0]);
                        exit(EXIT_SUCCESS);

		case 'K':
		case 'k':
		case 'S':
			if (key_len > 0)
				fatal("key already defined");
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
				key_len = num_key(optarg, key);
#else
				fatal("option -S|--keyserial unsupported");
#endif
				break;
			}
			break;

		case 'V':
		case 'v':
			if (iv_len > 0)
				fatal("IVs already defined!");
			switch (opt) {
			case 'V':
				iv_len = parse_iv(optarg,
						iv, algo_iv_len(algo));
				break;
			case 'v':
				iv_len = read_iv(optarg,
						iv, algo_iv_len(algo));
				break;
			}
			break;

                case 'P':
			pass_len = str_key(optarg, pass);
			break;
                case 'p':
			pass_len = read_key(optarg, pass, 0);
			break;

                case 'T':
			salt_len = parse_salt(optarg, salt, SALT_LEN);
			break;
                case 't':
			salt_len = read_salt(optarg, salt, SALT_LEN);
			break;

                case 'i':
			iterations = atoi(optarg);
			if (iterations == 0)
				fatal("invalid iterations number");
			break;

                default:
                        fatal("wrong option! Use -h for help");
                }
        }
	if (pass_len > 0) {
		if (salt_len == 0) {
			if (op == ALG_OP_ENCRYPT) {
				salt_len = generate_salt(salt);
				if (salt_len == 0)
					fatal("cannot generate random  salt");
				generated_salt = true;
			} else {
				salt_len = detect_salt(salt);
				if (salt_len == 0)
					fatal("no salt in encrypted data");
			}
		}
		dbg_dump(pass, pass_len, "pass:");
		dbg_dump(salt, salt_len, "salt:");
		key_len = algo_key_len(algo);
		iv_len = algo_iv_len(algo);
		pbkdf2(pass, pass_len, salt, salt_len, iterations,
			key, key_len, iv, iv_len);

	} else if (salt_len > 0)
		fatal("salt specified with no pass key!");
	if (key_len == 0)
                fatal("no key defined!");
	dbg_dump(key, key_len, "key:");
	if (iv_len == 0)
                fatal("no IVs defined!");
	dbg_dump(iv, iv_len, "iv:");

	fd = create_cipher_socket(algo, key, key_len);
	init_afalg_data(fd, op, iv, iv_len);

	if (generated_salt)
		write_salt(salt, salt_len);

	BUG_ON(algo_block_size(algo) > MAX_BLOCK_SIZE);
	last_nread = algo_block_size(algo) - 1;
	last_unwritten = 0;
	size = 0;
	do {
		nread = read_data(algo_block_size(algo), ibuf, op, &last_nread);
		if (nread == 0)
			break;

		size = pad_data(algo_block_size(algo), ibuf, nread);
		BUG_ON(size % algo_block_size(algo));
		process_data(fd, ibuf, obuf, size);
			
		write_data(algo_block_size(algo), obuf, size, op,
						unwritten, &last_unwritten);
	} while (nread > 0);
	if (last_unwritten)
		write_data(algo_block_size(algo), NULL, 0, op,
						unwritten, &last_unwritten);

	close(fd);
}
