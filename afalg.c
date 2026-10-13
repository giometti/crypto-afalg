/*
 * afalg.c - AF_ALG socket layer for Linux (libafalg)
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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <keyutils.h>
#include "afalg.h"

#ifndef SOL_ALG
#define SOL_ALG			279
#endif

/* The library is built with -fvisibility=hidden: this is its interface */
#define AFALG_EXPORT		__attribute__((visibility("default")))

/* What a keyring search looked for, and the key it found */
struct key_match {
	const char *type;
	const char *desc;
	key_serial_t found;
};

/* The keyrings a spec may name, each by one of two exact names */
static const struct {
	const char *names[2];
	key_serial_t id;
	const char *shown;
} keyrings[] = {
	{ { "@u", "user" },	KEY_SPEC_USER_KEYRING,		"@u" },
	{ { "@s", "session" },	KEY_SPEC_SESSION_KEYRING,	"@s" },
};

/* Fails with errno e, writing the reason into msg when one is asked for */
static int __attribute__((format(printf, 4, 5)))
fail(char *msg, size_t size, int e, const char *fmt, ...)
{
	va_list ap;

	if (msg && size > 0) {
		va_start(ap, fmt);
		vsnprintf(msg, size, fmt, ap);
		va_end(ap);
	}
	errno = e;
	return -1;
}

static bool is_name(const char *s, size_t len, const char *name)
{
	return strlen(name) == len && memcmp(s, name, len) == 0;
}

/* The index in keyrings[] of the keyring named by s, len long, or -1 */
static int keyring_by_name(const char *s, size_t len)
{
	size_t i, j;

	for (i = 0; i < sizeof(keyrings) / sizeof(keyrings[0]); i++)
		for (j = 0; j < 2; j++)
			if (is_name(s, len, keyrings[i].names[j]))
				return i;
	return -1;
}

/* Decimal digits only, positive and within key_serial_t */
static bool parse_serial(const char *s, key_serial_t *id)
{
	char *end;
	long v;

	if (*s < '0' || *s > '9')
		return false;
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno || *end != '\0' || v <= 0 || v > INT32_MAX)
		return false;
	*id = v;
	return true;
}

/*
 * One more key of the type and description searched, besides the one
 * found: desc is "<type>;<uid>;<gid>;<perm>;<description>"
 */
static int other_match(key_serial_t parent, key_serial_t key, char *desc,
		       int desc_len, void *data)
{
	const struct key_match *m = data;
	size_t tlen = strlen(m->type);
	char *p, *end;
	int i;

	if (!desc || key == m->found)
		return 0;
	p = desc;
	end = desc + desc_len;
	if ((size_t) desc_len <= tlen || memcmp(p, m->type, tlen) != 0 ||
	    p[tlen] != ';')
		return 0;
	for (i = 0; i < 4; i++) {
		p = memchr(p, ';', end - p);
		if (!p)
			return 0;
		p++;
	}
	return is_name(p, end - p, m->desc);
}

AFALG_EXPORT int afalg_socket(void)
{
	return socket(AF_ALG, SOCK_SEQPACKET, 0);
}

AFALG_EXPORT int afalg_bind(int s, const char *type, const char *name)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
	};

	/* Both fields must keep their terminating NUL */
	if (strlen(type) >= sizeof(sa.salg_type) ||
	    strlen(name) >= sizeof(sa.salg_name)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy((char *) sa.salg_type, type);
	strcpy((char *) sa.salg_name, name);

	return bind(s, (struct sockaddr *) &sa, sizeof(sa));
}

AFALG_EXPORT int afalg_set_key(int s, const struct afalg_key *key)
{
	switch (key->type) {
	case AFALG_KEY_RAW:
		return setsockopt(s, SOL_ALG, ALG_SET_KEY,
				  key->raw.data, key->raw.len);
	case AFALG_KEY_SERIAL:
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
		return setsockopt(s, SOL_ALG, ALG_SET_KEY_BY_KEY_SERIAL,
				  &key->serial, sizeof(key->serial));
#else
		errno = EOPNOTSUPP;
		return -1;
#endif
	}

	errno = EINVAL;
	return -1;
}

AFALG_EXPORT int afalg_accept(int s)
{
	return accept(s, NULL, 0);
}

AFALG_EXPORT int afalg_set_op_iv(int fd, int op, const void *iv,
				 size_t iv_len)
{
	char cbuf[CMSG_SPACE(sizeof(__u32)) +
		  CMSG_SPACE(sizeof(struct af_alg_iv) + AFALG_MAX_IV_LEN)]
		__attribute__((aligned(__alignof__(struct cmsghdr)))) = {0};
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *iv_data;
	struct iovec iov = {};

	if (iv_len > AFALG_MAX_IV_LEN) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * The kernel refuses unused room after the last message (EINVAL
	 * from 16 bytes on), so the length covers exactly the two.
	 */
	msg.msg_control = cbuf;
	msg.msg_controllen = CMSG_SPACE(sizeof(__u32)) +
			     CMSG_SPACE(sizeof(struct af_alg_iv) + iv_len);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(__u32));
	*(__u32 *) CMSG_DATA(cmsg) = op;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + iv_len);
	iv_data = (struct af_alg_iv *) CMSG_DATA(cmsg);
	iv_data->ivlen = iv_len;
	if (iv_len > 0)
		memcpy(iv_data->iv, iv, iv_len);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(fd, &msg, MSG_MORE) < 0)
		return -1;
	return 0;
}

AFALG_EXPORT ssize_t afalg_send(int fd, const void *buf, size_t len)
{
	return send(fd, buf, len, MSG_MORE);
}

AFALG_EXPORT ssize_t afalg_recv(int fd, void *buf, size_t len)
{
	return read(fd, buf, len);
}

AFALG_EXPORT int afalg_key_from_spec(const char *spec, struct afalg_key *key,
				     char *msg, size_t size)
{
	const char *ptype, *pdesc, *comma;
	struct key_match m;
	key_serial_t keyring_id, num;
	char type[64];
	int k, e;

	/* The simple form "<serial>" */
	comma = strchr(spec, ',');
	if (!comma) {
		if (!parse_serial(spec, &num))
			return fail(msg, size, EINVAL,
				    "invalid key serial number \"%s\"", spec);
		goto found;
	}

	/* The form "[<keyring>,]<type>,<description>", @u by default */
	k = 0;
	ptype = spec;
	pdesc = strchr(comma + 1, ',');
	if (pdesc) {
		k = keyring_by_name(spec, comma - spec);
		if (k < 0)
			return fail(msg, size, EINVAL,
				    "unknown keyring name \"%.*s\"",
				    (int) (comma - spec), spec);
		ptype = comma + 1;
	} else
		pdesc = comma;

	if (pdesc == ptype)
		return fail(msg, size, EINVAL, "empty key type in \"%s\"",
			    spec);
	if ((size_t) (pdesc - ptype) >= sizeof(type))
		return fail(msg, size, EINVAL, "key type too long");
	memcpy(type, ptype, pdesc - ptype);
	type[pdesc - ptype] = '\0';
	pdesc++;
	if (*pdesc == '\0')
		return fail(msg, size, EINVAL,
			    "empty key description in \"%s\"", spec);

	keyring_id = keyctl_get_keyring_ID(keyrings[k].id, 0);
	if (keyring_id < 0) {
		e = errno;
		return fail(msg, size, e, "cannot get keyring ID: %s",
			    strerror(e));
	}
	num = keyctl_search(keyring_id, type, pdesc, 0);
	if (num < 0) {
		e = errno;
		return fail(msg, size, e,
			    "cannot get ID for %s key %s in keyring %s: %s",
			    type, pdesc, keyrings[k].shown, strerror(e));
	}

	/*
	 * The search descends into the keyrings linked to this one and takes
	 * the first key it meets, so a name held twice is refused. Only the
	 * keyrings the caller can read are counted.
	 */
	m.type = type;
	m.desc = pdesc;
	m.found = num;
	if (recursive_key_scan(keyring_id, other_match, &m) > 0)
		return fail(msg, size, ENOTUNIQ,
			    "more than one %s key %s in keyring %s",
			    type, pdesc, keyrings[k].shown);

found:
	key->type = AFALG_KEY_SERIAL;
	key->serial = num;
	return 0;
}
