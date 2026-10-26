/*
 * kc-afalg.c - the AF_ALG backend of libkcrypto
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include "kc-backend.h"

#ifndef SOL_ALG
#define SOL_ALG			279
#endif

/* The socket bound to an algorithm, and the one of an operation */
struct kc_tfm {
	int fd;
};

struct kc_op {
	int fd;
};

/* A name the library promises to take is one bind() takes */
_Static_assert(KC_NAME_MAX + 1 ==
	       sizeof(((struct sockaddr_alg *) 0)->salg_name),
	       "KC_NAME_MAX is not what struct sockaddr_alg holds");

/* Both fields keep their terminating NUL; too long is a wrong argument */
static int fill_sockaddr(struct sockaddr_alg *sa, const char *type,
			 const char *name, struct kc_error *e)
{
	memset(sa, 0, sizeof(*sa));
	sa->salg_family = AF_ALG;
	if (strlen(type) >= sizeof(sa->salg_type) ||
	    strlen(name) >= sizeof(sa->salg_name))
		return kc_fail(e, KC_USAGE, ENAMETOOLONG, "bind(): %s",
			       strerror(ENAMETOOLONG));
	strcpy((char *) sa->salg_type, type);
	strcpy((char *) sa->salg_name, name);
	return KC_OK;
}

/*
 * The kernel decides, with a bind(): a template such as hmac(sha256) is
 * listed in /proc/crypto only once something has used it since the boot,
 * and a bind() is what builds it. ENOENT is its "no"; another failure,
 * such as ENOMEM, is no answer.
 */
static int afalg_available(const char *type, const char *name,
			   struct kc_error *e)
{
	struct sockaddr_alg sa;
	int s, ret, err, status;

	status = fill_sockaddr(&sa, type, name, e);
	if (status)
		return status;
	s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "socket(AF_ALG): %s",
			       strerror(err));
	}
	ret = bind(s, (struct sockaddr *) &sa, sizeof(sa));
	err = errno;
	close(s);		/* intentionally ignored */
	if (ret < 0)
		return kc_fail(e, err == ENOENT ? KC_REFUSED : KC_FAILED, err,
			       "bind(): %s", strerror(err));
	return kc_ok(e);
}

/* As in afalg_available(), ENOENT from the bind() is the kernel's "no" */
static int afalg_open(struct kc_tfm **t, const char *type, const char *name,
		      struct kc_error *e)
{
	struct sockaddr_alg sa;
	struct kc_tfm *tfm;
	int err, status;

	*t = NULL;
	tfm = malloc(sizeof(*tfm));
	if (!tfm)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	tfm->fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfm->fd < 0) {
		err = errno;
		free(tfm);
		return kc_fail(e, KC_FAILED, err, "socket(AF_ALG): %s",
			       strerror(err));
	}
	status = fill_sockaddr(&sa, type, name, e);
	if (!status && bind(tfm->fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		err = errno;
		status = kc_fail(e, err == ENOENT ? KC_REFUSED : KC_FAILED,
				 err, "bind(): %s", strerror(err));
	}
	if (status) {
		close(tfm->fd);		/* intentionally ignored */
		free(tfm);
		return status;
	}
	*t = tfm;
	return kc_ok(e);
}

/*
 * An empty raw key is still set: a keyed algorithm refuses to work until
 * a key has been set
 */
static int afalg_set_key(struct kc_tfm *t, const struct kc_key *k,
			 struct kc_error *e)
{
	int ret, err;

	switch (k->type) {
	case KC_KEY_RAW:
		if (setsockopt(t->fd, SOL_ALG, ALG_SET_KEY, k->data,
			       k->len) < 0) {
			err = errno;
			return kc_fail(e, KC_FAILED, err,
				       "setsockopt(ALG_SET_KEY): %s",
				       strerror(err));
		}
		return kc_ok(e);
	case KC_KEY_SERIAL:
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
		ret = setsockopt(t->fd, SOL_ALG, ALG_SET_KEY_BY_KEY_SERIAL,
				 &k->serial, sizeof(k->serial));
		err = errno;
#else
		ret = -1;
		err = EOPNOTSUPP;
#endif
		if (ret < 0)
			return kc_fail(e, KC_FAILED, err, "setsockopt(%s): %s",
				       "ALG_SET_KEY_BY_KEY_SERIAL",
				       strerror(err));
		return kc_ok(e);
	}
	return kc_fail(e, KC_USAGE, EINVAL, "unknown key type %d", k->type);
}

static void afalg_close(struct kc_tfm *t)
{
	close(t->fd);		/* intentionally ignored */
	free(t);
}

static int afalg_start(struct kc_tfm *t, struct kc_op **op,
		       struct kc_error *e)
{
	struct kc_op *o;
	int err;

	*op = NULL;
	o = malloc(sizeof(*o));
	if (!o)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	o->fd = accept(t->fd, NULL, 0);
	if (o->fd < 0) {
		err = errno;
		free(o);
		return kc_fail(e, KC_FAILED, err, "accept(): %s",
			       strerror(err));
	}
	*op = o;
	return kc_ok(e);
}

/*
 * The direction and the IV of a cipher; the length covers exactly the two
 * messages, since the kernel refuses unused room after the last one (EINVAL
 * from 16 bytes on)
 */
static int afalg_set_op_iv(struct kc_op *op, int encrypt, const void *iv,
			   size_t iv_len, struct kc_error *e)
{
	char cbuf[CMSG_SPACE(sizeof(__u32)) +
		  CMSG_SPACE(sizeof(struct af_alg_iv) + KC_BLOCK_MAX)]
		__attribute__((aligned(__alignof__(struct cmsghdr)))) = { 0 };
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct af_alg_iv *iv_data;
	struct iovec iov = { 0 };
	int err;

	if (iv_len > KC_BLOCK_MAX)
		return kc_fail(e, KC_USAGE, EINVAL, "invalid IV length %zu",
			       iv_len);
	msg.msg_control = cbuf;
	msg.msg_controllen = CMSG_SPACE(sizeof(__u32)) +
			     CMSG_SPACE(sizeof(struct af_alg_iv) + iv_len);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(__u32));
	*(__u32 *) CMSG_DATA(cmsg) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

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

	if (sendmsg(op->fd, &msg, MSG_MORE) < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "sendmsg(): %s",
			       strerror(err));
	}
	return kc_ok(e);
}

/*
 * Always with MSG_MORE: the data continue one operation, so a cipher
 * chains its IV and a hash covers every call up to the read
 */
static int afalg_send(struct kc_op *op, const void *buf, size_t len,
		      struct kc_error *e)
{
	const char *p = buf;
	ssize_t n;
	int err;

	while (len > 0) {
		n = send(op->fd, p, len, MSG_MORE);
		if (n < 0) {
			err = errno;
			return kc_fail(e, KC_FAILED, err, "sendmsg(): %s",
				       strerror(err));
		}
		if (n == 0)
			return kc_fail(e, KC_FAILED, 0,
				       "too few data sent to the kernel!");
		p += n;
		len -= n;
	}
	return kc_ok(e);
}

/* A digest longer than the room is cut by the kernel, which says so */
static int afalg_recv(struct kc_op *op, void *buf, size_t len, size_t *got,
		      struct kc_error *e)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t n;
	int err;

	n = recvmsg(op->fd, &msg, 0);
	if (n < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "read(): %s",
			       strerror(err));
	}
	if (msg.msg_flags & MSG_TRUNC)
		return kc_fail(e, KC_USAGE, EMSGSIZE, "read(): %s",
			       strerror(EMSGSIZE));
	*got = n;
	return kc_ok(e);
}

static void afalg_end(struct kc_op *op)
{
	close(op->fd);		/* intentionally ignored */
	free(op);
}

const struct kc_backend kc_afalg_backend = {
#ifdef ALG_SET_KEY_BY_KEY_SERIAL
	.key_serial	= true,
#endif
	.available	= afalg_available,
	.open		= afalg_open,
	.set_key	= afalg_set_key,
	.close		= afalg_close,
	.start		= afalg_start,
	.set_op_iv	= afalg_set_op_iv,
	.send		= afalg_send,
	.recv		= afalg_recv,
	.end		= afalg_end,
};
