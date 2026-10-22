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
#define MAX_PASS_LEN		1024	/* as openssl enc -pass file: */
#define MAX_IV_LEN		32
#define SALT_LEN		8

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
			kernel_has_algo("skcipher",
					algo_kname(algo)) ? '-' : 'x',
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
                if (kernel_has_algo("skcipher", kname))
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

/*
 * As openssl enc -pass file: only the first line, at most size - 1
 * characters; fgets() and not read_file() since the file may be a pipe
 */
static size_t read_pass(const char *file, char *pass, size_t size)
{
	FILE *f;
	size_t len;
	int c;

	f = fopen(file, "r");
	if (!f)
		fatal("cannot open pass file %s: %m", file);
	if (!fgets(pass, size, f))
		fatal("cannot read pass file %s", file);

	/* A full buffer is a truncation only if the line goes on */
	len = strcspn(pass, "\n");
	if (len == size - 1) {
		c = fgetc(f);
		if (c != EOF && c != '\n')
			err("warning: passphrase in %s truncated to %zu "
				"characters, as openssl does", file, len);
	}
	fclose(f);		/* intentionally ignored */

	return len;
}

static size_t detect_salt(char *salt)
{
	char marker[] = "Salted__";
	size_t size;

	size = fread(salt, 1, strlen(marker), stdin);
	if (size != strlen(marker))
		fatal("cannot read header");
	if (memcmp(marker, salt, strlen(marker)) != 0)
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

static size_t read_data(char *ibuf)
{
	size_t size;

	size = fread(ibuf, 1, BUF_SIZE, stdin);
	/* A short read is the end of the input only if it is not an error */
	if (size < BUF_SIZE && ferror(stdin))
		fatal("cannot read input: %m");
	return size;
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
		"to get help use:\n\t%s %s help|-h|--help\n",
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
                "    -V|--iv <val>           : hex value iv\n"
                "    -v|--ivfile <name>      : iv from file\n");
        fprintf(stderr,
                "where <PASS> can be one of:\n"
                "    -P|--pass <str>         : passkey\n"
                "    -p|--passfile <name>    : passkey from file\n"
                "where <SALT> can be one of:\n"
                "    -T|--salt <val>         : hex value salt\n"
                "    -t|--saltfile <name>    : salt from file\n");
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
	fprintf(stderr,
		"NOTE: keyring key can be:\n"
		"      - a simple serial number, or\n"
		"      - a symbolic name as [<keyring>,]<type>,<name>, with\n"
		"        <keyring> @u (user, the default) or @s (session)\n");
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
	bool encrypt;
	struct kc_cipher *c;
	struct kc_error e;
	enum afalg_algo_e algo;
	char key[MAX_KEY_LEN], iv[MAX_IV_LEN];
	size_t key_len = 0, iv_len = 0;
	struct kc_key *kkey = NULL;
	char passbuf[MAX_PASS_LEN], *pass = passbuf, salt[SALT_LEN];
	size_t pass_len = 0, salt_len = 0;
	int iterations = 10000;	/* the default */
	bool generated_salt = false;
	char ibuf[BUF_SIZE], obuf[BUF_SIZE + MAX_BLOCK_SIZE];
	size_t nread, olen;

	/* Check for common options */
        if (argc < 2) {
		list_ciphers();
		exit(EXIT_SUCCESS);
	}
        if (strcmp("check-kalgo", argv[1]) == 0) {
                if (argc < 3)
                        fatal("must specify a name");
                exit(check_cipher(argv[2]) ? EXIT_SUCCESS : EXIT_FAILURE);
        }
	if (strcmp("help", argv[1]) == 0 ||
	    strcmp("-h", argv[1]) == 0 ||
	    strcmp("--help", argv[1]) == 0) {
		usage_cipher(argv[0]);
		exit(EXIT_SUCCESS);
	}

	/* Parse command line */
	encrypt = argv[0][0] == 'e';
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
			if (key_len > 0 || kkey)
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
				spec_key(optarg, &kkey);
#else
				fatal("option -S|--keyserial unsupported");
#endif
				break;
			}
			break;

		case 'V':
		case 'v':
			if (iv_len > 0)
				fatal("IV already defined!");
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
			pass_len = str_key(optarg, &pass);
			break;
                case 'p':
			pass = passbuf;
			pass_len = read_pass(optarg, pass, MAX_PASS_LEN);
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
			if (encrypt) {
				salt_len = generate_salt(salt);
				if (salt_len == 0)
					fatal("cannot generate random salt");
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
		kc_key_free(kkey);
		kkey = NULL;
		iv_len = algo_iv_len(algo);
		pbkdf2(pass, pass_len, salt, salt_len, iterations,
			key, key_len, iv, iv_len);

	} else if (salt_len > 0)
		fatal("salt specified with no pass key!");
	if (!kkey) {
		if (key_len == 0)
			fatal("no key defined!");
		dbg_dump(key, key_len, "key:");
		if (kc_key_raw(&kkey, key, key_len, &e))
			fatal("%s", e.msg);
	}
	if (iv_len == 0)
                fatal("no IV defined!");
	dbg_dump(iv, iv_len, "iv:");

	c = open_cipher(algo, kkey, encrypt, iv, iv_len);

	if (generated_salt)
		write_salt(salt, salt_len);

	BUG_ON(algo_block_size(algo) > MAX_BLOCK_SIZE);
	BUG_ON(algo_block_size(algo) != iv_len);
	do {
		nread = read_data(ibuf);
		if (nread == 0)
			break;

		/*
		 * Only the last read can be short; a ciphertext whose length
		 * is wrong is refused before any of that read is written
		 */
		if (!encrypt && nread % algo_block_size(algo))
			fatal("bad decrypt (wrong final block length)");
		if (kc_cipher_update(c, ibuf, nread, obuf, &olen, &e))
			fatal("%s", e.msg);
		write_output(obuf, olen);
	} while (nread > 0);
	if (kc_cipher_final(c, obuf, &olen, &e))
		fatal("%s", e.msg);
	write_output(obuf, olen);
	flush_output();

	kc_cipher_free(c);
	kc_key_free(kkey);
}
