/*
 * crypto-afalg.c - Simple AF_ALG implementation for Linux
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

#include <keyutils.h>
#include <regex.h>
#include "crypto-afalg.h"

/*
 * Global variables & definitions
 */

int debug_level;
char *use_driver;

/*
 * Known Algo data
 */

const struct afalg_algo_data_s afalg_algo_data[] = {
        [AFALG_ALGO_CIPHER_AES128_CBC] = {
                .name           = "aes-128-cbc",
                .kname          = "cbc(aes)",
                .block_size     = 16,
                .key_len	= 16,
		.type		= AFALG_TYPE_CIPHER,
                .cipher.iv_len	= 16,
        },
        [AFALG_ALGO_CIPHER_AES256_CBC] = {
                .name           = "aes-256-cbc",
                .kname          = "cbc(aes)",
                .block_size     = 16,
                .key_len	= 32,
		.type		= AFALG_TYPE_CIPHER,
                .cipher.iv_len 	= 16,
        },
        [AFALG_ALGO_CIPHER_AES256_CBC_CAAM] = {
                .name           = "caam(aes-256-cbc)",
                .kname          = "tk(cbc(aes))",
                .block_size     = 16,
                .key_len	= 52,
		.type		= AFALG_TYPE_CIPHER,
                .cipher.iv_len	= 16,
        },
        [AFALG_ALGO_HASH_SHA256] = {
                .name           = "sha-256",
                .kname          = "sha256",
                .block_size     = 64,
		.type		= AFALG_TYPE_HASH,
                .hash.digest_size = 32,
        },
        [AFALG_ALGO_HASH_HMAC_SHA256] = {
                .name           = "hmac-sha-256",
                .kname          = "hmac(sha256)",
                .block_size     = 64,
                .key_len	= 32,
		.type		= AFALG_TYPE_HASH,
                .hash.digest_size = 32,
        },
};

/*
 * Common functions
 */

size_t fsize(FILE *f)
{
        size_t s;

        fseek(f, 0, SEEK_END);
        s = ftell(f);
        fseek(f, 0, SEEK_SET);

        return s;
}

bool is_in_proc_crypto(const char *type, const char *name, const char *driver)
{
        FILE* f;
        char line[256];
	regmatch_t matches[2];
	const char *ahash = "ahash", *shash = "shash";
	const char *n_pattern = "^name[[:space:]]+: ([^\n]+)\n$",
		   *t_pattern = "^type[[:space:]]+: ([^\n]+)\n$",
		   *d_pattern = "^driver[[:space:]]+: ([^\n]+)\n$";
	regex_t n_regex, t_regex, d_regex;
	char n[256], t[256], d[256];
	int ret;
        bool res = false;

	ret = regcomp(&n_regex, n_pattern, REG_EXTENDED);
	if (ret < 0)
		fatal("cannot compile n_regex");
	ret = regcomp(&t_regex, t_pattern, REG_EXTENDED);
	if (ret < 0)
		fatal("cannot compile t_regex");
	ret = regcomp(&d_regex, d_pattern, REG_EXTENDED);
	if (ret < 0)
		fatal("cannot compile d_regex");

        f = fopen("/proc/crypto", "r");
        if (!f)
                fatal("cannot open file /proc/crypto");

	n[0] = t[0] = d[0] = '\0';
        while (fgets(line, sizeof(line), f)) {
		/* New block */
		if (strlen(line) <= 1) {
			if (strcmp("hash", type) == 0 &&
			    strcmp(ahash, t) && strcmp(shash, t))
				goto reset;
			if (strcmp(name, n))
				goto reset;
			if (driver && strcmp(driver, d))
				goto reset;
			res = true;
			break;
		}

		/* Check for "type         : <TYPE>" */
		ret = regexec(&t_regex, line, ARRAY_SIZE(matches), matches, 0);
		if (ret == 0) {
			strncpy(t, line + matches[1].rm_so,
				matches[1].rm_eo - matches[1].rm_so);
			t[matches[1].rm_eo - matches[1].rm_so] = '\0';

			continue;
		}

		/* Check for "name         : <NAME>" */
		ret = regexec(&n_regex, line, ARRAY_SIZE(matches), matches, 0);
		if (ret == 0) {
			strncpy(n, line + matches[1].rm_so,
				matches[1].rm_eo - matches[1].rm_so);
			n[matches[1].rm_eo - matches[1].rm_so] = '\0';

			continue;
		}

		/* Check for "driver       : <DRIVER>" */
		ret = regexec(&d_regex, line, ARRAY_SIZE(matches), matches, 0);
		if (ret == 0) {
			strncpy(d, line + matches[1].rm_so,
				matches[1].rm_eo - matches[1].rm_so);
			d[matches[1].rm_eo - matches[1].rm_so] = '\0';

			continue;
		}

		continue;
reset:
			n[0] = t[0] = d[0] = '\0';
        }

	regfree(&n_regex);
	regfree(&t_regex);
	regfree(&d_regex);
        fclose(f);

        return res;
}

size_t parse_str(const char *label, const char *str, char *data, size_t len)
{
        size_t i;
        int ret;

        if (strlen(str) != 2 * len)
                fatal("invalid %s length!", label);
        for (i = 0; i < len; i++) {
                ret = sscanf(str + 2 * i, "%02x", (unsigned int *) &data[i]);
                if (ret != 1)
                        fatal("cannot parse %s at byte #%lu", label, i);
        }

        return i;
}

size_t parse_key(const char *str, char *key, size_t key_len)
{
        return parse_str("key", str, key, key_len);
}

size_t read_file(const char *label, const char *file, char *data, size_t len)
{
        size_t i;
        FILE *f;
        int ret;

        f = fopen(file, "r");
        if (!f)
                fatal("cannot open %s file %s: %m", label, file);

        i = fsize(f);
        if ((len > 0) && (i != len))
                fatal("invalid %s length!", label);
        ret = fread(data, 1, i, f);
	if (((len > 0) && (ret != len)) ||
	    ((len == 0) && (ret <= 0)))
			fatal("cannot read %s file", label);

        return ret;
}

size_t read_key(const char *file, char *key, size_t key_len)
{
        return read_file("key", file, key, key_len);
}

/*
 * Retrieve key ID from keyname which can be:
 *     - <num>
 *     - [<keyring>,]<type>,<name>
 */
size_t num_key(const char *str, char *key)
{
	char *keyring = "@u";
	char type[64];
	const char *pname, *ptype;
	key_serial_t key_spec = KEY_SPEC_USER_KEYRING;
	key_serial_t keyring_id;
	int32_t num;

	/* The the simple form "<num>" */
	ptype = strchr(str, ',');
	if (ptype == 0) {
		num = atoi(str);
		if (num == 0)
			fatal("invalid key serial number");
		goto exit;
	}

	/* OK, let's try to parse the second form */
	pname = strchr(ptype + 1, ',');
	if (pname == 0) {
		pname = ptype;
		ptype = str;
	}

	if (ptype != str) {
		if (strncmp(str, "session", ptype - str) == 0 ||
		    strncmp(str, "@s", ptype - str) == 0) {
			key_spec = KEY_SPEC_SESSION_KEYRING;
			keyring = "@s";
		} else if (strncmp(str, "user", ptype - str) == 0 ||
			 strncmp(str, "@u", ptype - str) == 0)
			/* nop */;
		else
			fatal("unkown keyring name \"%.*s\"",
					(int) (ptype - str), str);

		ptype++;
	}

	keyring_id = keyctl_get_keyring_ID(key_spec, 0);
	if (keyring_id < 0)
		fatal("cannot get keyring ID: %m");
	dbg("keyring %s id=%ld", keyring, (long) keyring_id);

	BUG_ON(pname - ptype >= 64);
	strncpy(type, ptype, pname - ptype);
	type[pname - ptype] = '\0';
	pname++;
	dbg("type=%s name=%s", type, pname);
	num = keyctl_search(keyring_id, type, pname, 0);
	if (num < 0)
		fatal("cannot get ID for %s key %s in keyring %s: %m",
				type, pname, keyring);

exit:
	dbg("key_id=%ld", (long) num);
	*((int32_t *) key) = num;

	return sizeof(num);
}

size_t str_key(char *str, char **key)
{
	*key = str;
	return strlen(str);
}

int __init_afalg_socket(const char *type, enum afalg_algo_e algo,
			char *key, size_t key_len)
{
        int s;
        struct sockaddr_alg sa = {
                .salg_family = AF_ALG,
        };
        int sockopt = key_len == sizeof(int32_t) ?
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
                        ALG_SET_KEY_BY_KEY_SERIAL
#else
                        0
#endif
                        : ALG_SET_KEY;
        int ret;

	if (!is_in_proc_crypto(type, algo_kname(algo), use_driver)) {
		if (use_driver)
			fatal("driver \"%s\" is not available "
				"or not valid %s(%s) algo",
					use_driver, type, algo_kname(algo));
		else
			fatal("algo \"%s\" is not available "
				"or not valid %s algo",
					algo_kname(algo), type);
	}

        strcpy((char *) sa.salg_type, type);
        strcpy((char *) sa.salg_name, use_driver ?
					use_driver : algo_kname(algo));

        ret = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (ret < 0)
                fatal("socket(AF_ALG): %m");
        s = ret;

        ret = bind(s, (struct sockaddr *)&sa, sizeof(sa));
        if (ret < 0)
                fatal("bind(): %m");

	/*
	 * A NULL key means none; an empty one is still set, since a keyed
	 * algorithm refuses to work until a key has been set.
	 */
        if (key) {
                ret = setsockopt(s, SOL_ALG, sockopt, key, key_len);
                if (ret < 0)
                        fatal("setsockopt(ALG_SET_KEY): %m");
        }

        return s;
}

int __get_afalg_socket(int s)
{
	int ret;

	ret = accept(s, NULL, 0);
	if (ret < 0)
		fatal("accept(): %m");

	return ret;
}

int create_afalg_socket(const char *type, enum afalg_algo_e algo,
			char *key, size_t key_len)
{
        int s;
        int ret;

	s = __init_afalg_socket(type, algo, key, key_len);

        ret = __get_afalg_socket(s);
        close(s);

        return ret;
}

/*
 * Main
 */

static void usage(void)
{
        fprintf(stderr,
                "usage: %s [ -d|--debug ] [ -h|--help ] [--version] "
		"[ --force-driver <name> ] "
		"<command> ...\n", NAME);
        fprintf(stderr, "  <command> can be:\n"
                "    encrypt <algo> <opts> : encrypt data\n"
                "    decrypt <algo> <opts> : decrypt data\n"
                "    hash <algo> <opts>    : compute data hash\n");
}

static void version(void)
{
        printf("%s %s\n", NAME, __CRYPTO_AFALG_VERSION__);
	printf("Copyright (C) 2025 Rodolfo Giometti <giometti@enneenne.com>\n");
	printf("This is free software, and you are welcome to redistribute it under\n"
		"terms of the GNU General Public License as published by the Free Software\n"
		"Foundation, either version 3 of the License, or any later version.\n");
	printf("*** This program comes with ABSOLUTELY NO WARRANTY. ***\n");
}

int main(int argc, char *argv[])
{
        int opt;
        int long_index = 0;
        static struct option options[] = {
                { "force-driver", required_argument,	NULL, 1000 },
                { "version",	no_argument,		NULL, 1001 },
                { "debug",	no_argument,		NULL, 'd' },
                { "help",	no_argument,		NULL, 'h' },
                { 0, 0, 0, 0 }
        };

        while ((opt = getopt_long(argc, argv, "+dh", options,
                            &long_index)) >= 0) {
                switch (opt) {
                case 1000:
                        use_driver = optarg;
                        break;

                case 'd':
                        incr_debug(1);
                        break;

                case 'h':
                        usage();
                        exit(EXIT_SUCCESS);

                case 1001:
                        version();
                        exit(EXIT_SUCCESS);

                default:
                        fatal("wrong option! Use -h for help");
                }
        }
        if (argc - optind < 1)
                fatal("invalid command line! Must specify a command");
	if (use_driver)
		dbg("forcing driver %s", use_driver);

        if (strcmp("encrypt", argv[optind]) == 0 ||
	    strcmp("decrypt", argv[optind]) == 0)
		do_crypt(argc - optind, &argv[optind]);
	else if (strcmp("hash", argv[optind]) == 0)
		do_hash(argc - optind, &argv[optind]);
	else
		fatal("invalid command \"%s\"", argv[optind]);

	return 0;
}
