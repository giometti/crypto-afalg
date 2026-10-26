# libkcrypto

`libkcrypto.so.0` gives user space the cryptography of the Linux kernel, with the keys where the kernel keeps them, in place of OpenSSL's `libcrypto`, which holds its keys in the program's memory. crypto-afalg is built on it, and craf takes its cipher drivers from it; craf still uses [libafalg](libafalg.md) for the rest. The library prints nothing and never exits: what to say about a failure, and what to do then, is the caller's.

Today it reaches the kernel through `AF_ALG`, its only backend. The interface is made of keys, algorithms and drivers, not of sockets, so that a backend added later changes nothing for its users; the type names (`skcipher`, `hash`) and the messages still come from `AF_ALG`.

## Stability

The interface, declared in `kcrypto.h`, is **unstable until version 1.0**. Its soname stays `libkcrypto.so.0` meanwhile, so a change does not stop an older program from loading a newer library: rebuild the programs linked against it whenever you update it. The exception is `struct kc_error`, which the caller allocates: a change of its size, `KC_MSG_MAX` included, changes the soname, even before 1.0.

## Building and linking

`make` builds `libkcrypto.so.0` together with the tools, and `make install` installs it with its link-time name `libkcrypto.so` and the header `kcrypto.h` (see "How to Install" in the README). Compile a program with `#include <kcrypto.h>` and link it with `-lkcrypto` against an installed copy: the build directory holds no `libkcrypto.so`. The library itself needs `libkeyutils` (see Requirements in the README). Like the rest of the project, the library is licensed under the GNU GPL v3.0 or later.

## Errors

Every function that can fail returns one of four statuses and, when its last argument, a `struct kc_error *`, is not NULL, fills it in with the same status, the `errno` of the cause (0 when there is none) and a message:

| status | meaning |
|---|---|
| `KC_OK` (0) | done |
| `KC_REFUSED` (1) | the answer is no: the kernel has no such algorithm, `/proc/crypto` lists no such driver, a ciphertext of the wrong length or with a wrong padding ("bad decrypt"), an `openssl enc` header that is truncated or does not start with `Salted__` |
| `KC_USAGE` (2) | an argument is wrong: an unknown type, a name too long, a malformed key spec, no room for the digest, a cipher without a key or with an IV of 0 bytes or longer than `KC_BLOCK_MAX`, a hash or a cipher used after its end, no iteration or no output for PBKDF2 |
| `KC_FAILED` (3) | it could not be done: a socket that does not open, a key that is not found or that cannot be used, `/proc/crypto` that cannot be read; also an HMAC without a key, at its first update or at its final (`ENOKEY`), and a key given to a hash that takes none, such as `sha256`, at the opening (`ENOSYS`) |

`KC_REFUSED` and `KC_FAILED` are kept apart on purpose: a "no" is an answer, a failure is the lack of one.

## Functions

| function | what it does |
|---|---|
| `kc_algo_available(type, name, e)` | asks the kernel whether it has an algorithm or a driver by its exact name (`type` is `skcipher` or `hash`, a name at most `KC_NAME_MAX` characters long, which is what a socket takes): `KC_REFUSED` is its no, `KC_FAILED` no answer; the kernel builds an algorithm made from a template, such as `hmac(sha256)`, when asked, and may load a module |
| `kc_driver_check(type, driver, algo, e)` | checks that `/proc/crypto` lists `driver` as a driver of `algo` of a type a `type` socket takes (`skcipher` and `lskcipher` for `skcipher`, and the `blkcipher`, `ablkcipher` and `givcipher` of the kernels before 5.5; `ahash` and `shash` for `hash`); the kernel takes a driver of another algorithm without any error, so a driver chosen by name needs this check. `KC_REFUSED` when it is not listed so, `KC_FAILED` only when `/proc/crypto` cannot be read. It does not ask the kernel, so a driver the kernel builds from a template is listed only once something has used it since the boot; `kc_algo_available()` on its name builds it |
| `kc_driver_algo(type, driver, algo, size, e)` | the algorithm `/proc/crypto` lists `driver` for, among the types a `type` socket takes, as for `kc_driver_check()`, into `algo` of `size` bytes: `KC_REFUSED` when it lists no such driver, `KC_USAGE` (`ENAMETOOLONG`) when the name does not fit, `KC_FAILED` only when `/proc/crypto` cannot be read. Like `kc_driver_check()`, it does not ask the kernel |
| `kc_algo_listed(type, algo, e)` | whether `/proc/crypto` lists `algo` as the name of an algorithm, among the same types: `KC_REFUSED` when it does not, `KC_FAILED` only when it cannot be read; it tells the name of an algorithm given where a driver is expected |
| `kc_driver_for_algo(type, algo, driver, size, e)` | the driver the kernel takes for `algo`, into `driver` of `size` bytes (`KC_NAME_MAX + 1` is enough for one a socket can take), chosen as the kernel's `__crypto_alg_lookup()` does: the highest priority among the tested, not internal drivers `/proc/crypto` lists for it, the first one listed among equals. It asks the kernel first, as `kc_algo_available()` does, so that the driver of an algorithm made from a template is listed: `KC_REFUSED` when the kernel has no such algorithm, or `/proc/crypto` lists no driver of it that it would take; `KC_FAILED` when the kernel or `/proc/crypto` could not be asked; `KC_USAGE` (`ENAMETOOLONG`) when the name does not fit. Some drivers the kernel prefers cannot be used through `AF_ALG` (on i.MX, `cbc-aes-tee`): there, the caller names the driver |
| `kc_key_raw(&k, data, len, e)` | a key of raw bytes, copied; an empty one is a key too, as an HMAC takes it |
| `kc_key_spec(&k, spec, e)` | a keyring key, from a serial or from `[<keyring>,]<type>,<description>` as crypto-afalg `-S` takes it (see the README): a malformed spec, and a description that more than one key holds in the keyrings the caller can read, are `KC_USAGE`, a key that is not found `KC_FAILED`; a serial is taken as it is, not looked up. The kernel uses the key by its serial: its bytes never reach the program. What is opened with a keyring key is `KC_FAILED` where `kc_key_serial_supported()` is 0 (`EOPNOTSUPP`) or the kernel is older than Linux 6.2 (its `errno`) |
| `kc_key_serial_supported()` | 1 when the library can hand the kernel a keyring key, being built with an `<linux/if_alg.h>` that defines `ALG_SET_KEY_BY_KEY_SERIAL`, 0 otherwise; a program built against another copy of the headers asks this, not its own headers. The kernel takes keyring keys from Linux 6.2 |
| `kc_key_serial(k)` | the serial of a keyring key, 0 for raw bytes |
| `kc_key_free(k)` | clears raw bytes and frees the key |
| `kc_hash_open(&h, name, k, e)` | a hash or an HMAC, by the name of an algorithm or of a driver (check a driver chosen by name with `kc_driver_check()` first); `k` is NULL for an algorithm without a key, and can be freed once the hash is open; `KC_REFUSED` when the kernel has no such algorithm |
| `kc_hash_update(h, in, len, e)` | adds data, in as many calls as needed |
| `kc_hash_final(h, md, &md_len, e)` | gives the digest and ends the hash: `md_len` is the room in `md` on the way in, and the length of the digest on the way out; `KC_HASH_MAX` is always enough, and less room than the digest is `KC_USAGE`. After it, and after a call that fails, the hash can only be freed |
| `kc_hash_free(h)` | frees the hash |
| `kc_cipher_open(&c, name, k, encrypt, iv, iv_len, e)` | a block cipher in a mode whose IV is one block, such as CBC, by the name of an algorithm or of a driver, for encryption (`encrypt` not 0) or decryption, with the PKCS#7 padding, `KC_REFUSED` when the kernel has no such algorithm; `iv_len` is the block size too, at most `KC_BLOCK_MAX`, and `k` can be freed once the cipher is open |
| `kc_cipher_update(c, in, len, out, &out_len, e)` | takes any length and writes whole blocks into `out`, which needs room for `len + iv_len` bytes and must not overlap `in`, setting `out_len`; in decryption it holds the last block back |
| `kc_cipher_final(c, out, &out_len, e)` | writes the rest, at most `iv_len` bytes: in encryption the last block with its padding, a whole block of padding when the input is a multiple of the block; in decryption the last block without its padding, or `KC_REFUSED` when the length or the padding is wrong. This is not an authentication: a wrong IV, or a ciphertext changed in the middle, decrypts without any error, and what was written before a `KC_REFUSED` is to be discarded. It ends the cipher: after it, and after a call that fails, the cipher can only be freed |
| `kc_cipher_free(c)` | clears and frees the cipher |
| `kc_pbkdf2(hmac, pass, pass_len, salt, salt_len, iter, out, out_len, e)` | PBKDF2 (RFC 8018) over an HMAC by the name of the algorithm, such as `hmac(sha256)`, or of a driver of one, `KC_REFUSED` when the kernel has no such HMAC, `KC_FAILED` (`ENOSYS`) for a hash that is not an HMAC, such as `sha256`: `out_len` bytes into `out`; `iter` and `out_len` are at least 1 |
| `kc_openssl_header(buf, len, salt, e)` | the salt of the header that `openssl enc` writes before what it encrypts with a passphrase and a random salt, `Salted__` and 8 bytes, from the first `KC_OPENSSL_HEADER_LEN` bytes of the stream; `KC_REFUSED` when they do not start with `Salted__`, or when `len`, what the stream had, is shorter |
| `kc_openssl_header_make(buf, salt)` | writes such a header |

With these, a file of `openssl enc -pbkdf2` and its defaults is decrypted by reading the header, deriving `kc_pbkdf2()` over `hmac(sha256)`, 10000 iterations, as many bytes as the key and the IV together, the key first, and decrypting the rest of the file with them.

## A typical use

A cipher: a key, then the cipher opened with it, then the data through `kc_cipher_update()` in as many calls as needed, then `kc_cipher_final()`. A hash is the same with `kc_hash_open()`, `kc_hash_update()` and `kc_hash_final()`, which gives the digest.

This program encrypts a line with AES-128-CBC, by the algorithm name `cbc(aes)`, which lets the kernel choose the driver; a driver name, such as `cbc-aes-ce`, takes exactly that one (check it with `kc_driver_check()` first):

```c
#include <stdio.h>
#include <kcrypto.h>

int main(void)
{
	static const char key[] = "0123456789abcdef";
	static const char iv[16] = { 0 };
	static const char in[] = "Hello, kernel!\n";
	unsigned char out[sizeof(in) + 2 * KC_BLOCK_MAX];
	struct kc_cipher *c = NULL;
	struct kc_key *k = NULL;
	struct kc_error e;
	size_t len, last;

	if (kc_key_raw(&k, key, sizeof(key) - 1, &e) ||
	    kc_cipher_open(&c, "cbc(aes)", k, 1, iv, sizeof(iv), &e) ||
	    kc_cipher_update(c, in, sizeof(in) - 1, out, &len, &e) ||
	    kc_cipher_final(c, out + len, &last, &e)) {
		fprintf(stderr, "kcrypto: %s\n", e.msg);
		return 1;
	}
	fwrite(out, 1, len + last, stdout);
	kc_cipher_free(c);
	kc_key_free(k);
	return 0;
}
```

Its output is the same as that of `openssl enc -aes-128-cbc -K 30313233343536373839616263646566 -iv 00000000000000000000000000000000` on the same line.
