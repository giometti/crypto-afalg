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
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "afalg.h"

#ifndef SOL_ALG
#define SOL_ALG			279
#endif

/* The library is built with -fvisibility=hidden: this is its interface */
#define AFALG_EXPORT		__attribute__((visibility("default")))

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
