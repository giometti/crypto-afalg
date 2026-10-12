# libafalg

`libafalg.so.0` is the `AF_ALG` socket layer of crypto-afalg, as a shared library for other tools too. Each of its functions wraps one step of the `AF_ALG` interface of the Linux kernel: open a socket, bind it to an algorithm or a driver, set a key, open an operation, set its direction and IV, pass data in and read the result. The library prints nothing and never exits: what to say about a failure, and what to do then, is the caller's.

## Stability

The interface, declared in `afalg.h`, is **unstable until version 1.0**. Its soname stays `libafalg.so.0` meanwhile, so a change does not stop an older program from loading a newer library: rebuild the programs linked against it whenever you update it.

## Building and linking

`make` builds `libafalg.so.0` together with crypto-afalg, and `make install` installs it with its link-time name `libafalg.so` and the header `afalg.h` (see "How to Install" in the README). Compile a program with `#include <afalg.h>` and link it with `-lafalg` against an installed copy: the build directory holds no `libafalg.so`. Like the rest of the project, the library is licensed under the GNU GPL v3.0 or later.

## Errors

Every function returns -1 on failure and sets `errno`: the error of the system call it wraps, or one of the library's own, which the comment above the declarations in `afalg.h` lists. `afalg_set_op_iv()` returns 0 on success.

## Functions

| function | what it does |
|---|---|
| `afalg_socket()` | opens an `AF_ALG` socket |
| `afalg_bind(s, type, name)` | binds it to an algorithm or a driver by its exact name (`type` is `skcipher` or `hash`) |
| `afalg_set_key(s, key)` | sets a key, raw bytes or a keyring key by serial (`struct afalg_key`) |
| `afalg_accept(s)` | returns the socket of one operation |
| `afalg_set_op_iv(fd, op, iv, iv_len)` | sets encryption or decryption (`ALG_OP_ENCRYPT`, `ALG_OP_DECRYPT`) and the IV of a `skcipher` operation; `iv_len` must be the IV size of the cipher (the kernel refuses any other), at most `AFALG_MAX_IV_LEN` |
| `afalg_send(fd, buf, len)` | adds data to the one ongoing operation, always with `MSG_MORE`: a cipher chains its IV across calls, a hash digests every call up to `afalg_recv()` |
| `afalg_recv(fd, buf, len)` | reads its result |

## A typical use

A cipher: open a socket, bind it, set the key, open an operation, close the first socket (the operation keeps what it needs), set the direction and the IV, then send whole blocks and read as many bytes back. A hash is the same with `hash` and no `afalg_set_op_iv()`: send the data, in as many calls as needed, then read the digest.

This program encrypts one block with AES-128-CBC, by the algorithm name `cbc(aes)`, which lets the kernel choose the driver; a driver name, such as `cbc-aes-ce`, binds exactly that one:

```c
#include <stdio.h>
#include <unistd.h>
#include <afalg.h>

int main(void)
{
	static const char key[16] = "0123456789abcdef";
	static const char iv[16] = { 0 };
	static const char in[16] = "sixteen bytes!!";
	char out[16];
	struct afalg_key k = {
		.type = AFALG_KEY_RAW,
		.raw = { .data = key, .len = sizeof(key) },
	};
	int s, fd;

	s = afalg_socket();
	if (s < 0 || afalg_bind(s, "skcipher", "cbc(aes)") < 0 ||
	    afalg_set_key(s, &k) < 0) {
		perror("afalg");
		return 1;
	}
	fd = afalg_accept(s);
	close(s);
	if (fd < 0 || afalg_set_op_iv(fd, ALG_OP_ENCRYPT, iv, sizeof(iv)) < 0 ||
	    afalg_send(fd, in, sizeof(in)) != sizeof(in) ||
	    afalg_recv(fd, out, sizeof(out)) != sizeof(out)) {
		perror("afalg");
		return 1;
	}
	fwrite(out, 1, sizeof(out), stdout);
	close(fd);
	return 0;
}
```

Its output is the same as that of `openssl enc -aes-128-cbc -nopad -K 30313233343536373839616263646566 -iv 00000000000000000000000000000000` on the same 16 bytes.
