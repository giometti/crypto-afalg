# libkcrypto

`libkcrypto.so.0` gives user space the cryptography of the Linux kernel, with the keys where the kernel keeps them, in place of OpenSSL's `libcrypto`, which holds its keys in the program's memory. crypto-afalg and craf are built on it; it replaces `libafalg.so.0`, the `AF_ALG` socket layer that craf used up to v1.3.0. The library prints nothing and never exits: what to say about a failure, and what to do then, is the caller's.

Today it reaches the kernel through `AF_ALG`, its only backend. The interface is made of keys, algorithms and drivers, not of sockets, so that a backend added later changes nothing for its users; the type names (`skcipher`, `hash`) and the messages still come from `AF_ALG`.

## Stability

The interface, declared in `kcrypto.h`, is **unstable until version 1.0**. Its soname stays `libkcrypto.so.0` meanwhile, so a change does not stop an older program from loading a newer library: rebuild the programs linked against it whenever you update it. The exceptions are `struct kc_error` and `struct kc_pkey_info`, which the caller allocates: a change of their size, `KC_MSG_MAX` included, or of their layout, and a change of the values of `KC_PKEY_*`, which are the kernel's `KEYCTL_SUPPORTS_*`, change the soname, even before 1.0. `struct kc_pkey_info` has reserved fields, which the library sets to 0, so that a later version can answer more without changing it.

## Building and linking

`make` builds `libkcrypto.so.0` together with the tools, and `make install` installs it with its link-time name `libkcrypto.so` and the header `kcrypto.h` (see "How to Install" in the README). Compile a program with `#include <kcrypto.h>` and link it with `-lkcrypto` against an installed copy: the build directory holds no `libkcrypto.so`. The library itself needs `libkeyutils` (see Requirements in the README). Like the rest of the project, the library is licensed under the GNU GPL v3.0 or later.

## Errors

Every function that can fail returns one of four statuses and, when its last argument, a `struct kc_error *`, is not NULL, fills it in with the same status, the `errno` of the cause (0 when there is none) and a message:

| status | meaning |
|---|---|
| `KC_OK` (0) | done |
| `KC_REFUSED` (1) | the answer is no: the kernel has no such algorithm, `/proc/crypto` lists no such driver, a ciphertext of the wrong length or with a wrong padding ("bad decrypt"), an `openssl enc` header that is truncated or does not start with `Salted__`, a signature that does not hold ("verification failure") |
| `KC_USAGE` (2) | an argument is wrong: an unknown type, a name too long, a malformed key spec, no room for the digest, a cipher without a key or with an IV of 0 bytes or longer than `KC_BLOCK_MAX`, a hash or a cipher used after its end, no iteration or no output for PBKDF2, an empty certificate, a public key that is not one DER SEQUENCE or is longer than 16384 bytes, a key that is not a keyring key or no parameters for an asymmetric key, a digest of 0 bytes or longer than the key takes, an empty signature |
| `KC_FAILED` (3) | it could not be done: a socket that does not open, a key that is not found, that cannot be loaded or that cannot be used, parameters of an asymmetric key that the kernel does not take, `/proc/crypto` that cannot be read; also an HMAC without a key, at its first update or at its final (`ENOKEY`), and a key given to a hash that takes none, such as `sha256`, at the opening (`ENOSYS`) |

`KC_REFUSED` and `KC_FAILED` are kept apart on purpose: a "no" is an answer, a failure is the lack of one.

## Functions

| function | what it does |
|---|---|
| `kc_algo_available(type, name, e)` | asks the kernel whether it has an algorithm or a driver by its exact name (`type` is `skcipher` or `hash`, a name at most `KC_NAME_MAX` characters long, which is what a socket takes): `KC_REFUSED` is its no, `KC_FAILED` no answer; the kernel builds an algorithm made from a template, such as `hmac(sha256)`, when asked, and may load a module |
| `kc_driver_check(type, driver, algo, e)` | checks that `/proc/crypto` lists `driver` as a driver of `algo` of a type a `type` socket takes (`skcipher` and `lskcipher` for `skcipher`, and the `blkcipher`, `ablkcipher` and `givcipher` of the kernels before 5.5; `ahash` and `shash` for `hash`); the kernel takes a driver of another algorithm without any error, so a driver chosen by name needs this check. `KC_REFUSED` when it is not listed so, `KC_FAILED` only when `/proc/crypto` cannot be read. It does not ask the kernel, so a driver the kernel builds from a template is listed only once something has used it since the boot; `kc_algo_available()` on its name builds it |
| `kc_driver_algo(type, driver, algo, size, e)` | the algorithm `/proc/crypto` lists `driver` for, among the types a `type` socket takes, as for `kc_driver_check()`, into `algo` of `size` bytes: `KC_REFUSED` when it lists no such driver, `KC_USAGE` (`ENAMETOOLONG`) when the name does not fit, `KC_FAILED` only when `/proc/crypto` cannot be read. Like `kc_driver_check()`, it does not ask the kernel |
| `kc_algo_listed(type, algo, e)` | whether `/proc/crypto` lists `algo` as the name of an algorithm, among the same types: `KC_REFUSED` when it does not, `KC_FAILED` only when it cannot be read; it tells the name of an algorithm given where a driver is expected |
| `kc_driver_for_algo(type, algo, driver, size, e)` | the driver the kernel takes for `algo`, into `driver` of `size` bytes (`KC_NAME_MAX + 1` is enough for one a socket can take), chosen as the kernel's `__crypto_alg_lookup()` does: the highest priority among the tested, not internal drivers `/proc/crypto` lists for it, the first one listed among equals. It asks the kernel first, as `kc_algo_available()` does, so that the driver of an algorithm made from a template is listed: `KC_REFUSED` when the kernel has no such algorithm, or `/proc/crypto` lists no driver of it that it would take; `KC_FAILED` when the kernel or `/proc/crypto` could not be asked; `KC_USAGE` (`ENAMETOOLONG`) when the name does not fit. Some drivers the kernel prefers cannot be used through `AF_ALG` (on i.MX, `cbc-aes-tee`): there, the caller names the driver |
| `kc_cipher_sizes(name, &block, &iv_len, &key_min, &key_max, e)` | the sizes of an skcipher, by the name of an algorithm or of a driver, in bytes, as `/proc/crypto` lists them: its block, its IV (0 for a mode without one, such as `ecb`) and its shortest and longest key. It asks the kernel first, as `kc_algo_available()` does, so that a cipher made from a template is listed: `KC_REFUSED` when the kernel has no such cipher or `/proc/crypto` does not list it, `KC_FAILED` when the kernel or `/proc/crypto` could not be asked, or `/proc/crypto` lists the cipher without the four sizes, `KC_USAGE` (`ENAMETOOLONG`) for a name longer than `KC_NAME_MAX`. The sizes alone do not tell modes apart: `xts(aes)` and `cts(cbc(aes))` have the block and the IV of `cbc(aes)` |
| `kc_key_raw(&k, data, len, e)` | a key of raw bytes, copied; an empty one is a key too, as an HMAC takes it |
| `kc_key_spec(&k, spec, e)` | a keyring key, from a serial or from `[<keyring>,]<type>,<description>` as crypto-afalg `-S` takes it (see the README): a malformed spec, and a description that more than one key holds in the keyrings the caller can read, are `KC_USAGE`, a key that is not found `KC_FAILED`; a serial is taken as it is, not looked up. The kernel uses the key by its serial: its bytes never reach the program. What is opened with a keyring key is `KC_FAILED` where `kc_key_serial_supported()` is 0 (`EOPNOTSUPP`) or the kernel is older than Linux 6.2 (its `errno`) |
| `kc_key_serial_supported()` | 1 when the library can hand the kernel a keyring key, being built with an `<linux/if_alg.h>` that defines `ALG_SET_KEY_BY_KEY_SERIAL`, 0 otherwise; a program built against another copy of the headers asks this, not its own headers. The kernel takes keyring keys from Linux 6.2 |
| `kc_key_blob(&k, blob, len, e)` | the key of a trusted key blob, the bytes the kernel gives (`keyctl pipe` writes them in hex): loaded into the keyring of the calling thread, out of reach of any other process and gone with that thread, and so with the process, and used by its serial as a keyring key, so `kc_key_serial_supported()` and the kernel decide whether it can be used. Only the trust source that sealed the blob (a TPM, a TEE such as OP-TEE, CAAM) loads it: a blob it does not take is `KC_FAILED` with the kernel's `errno` (`ENODEV` for a kernel without trusted keys), an empty one `KC_USAGE`, as one too long for its hex form to be built; one the kernel refuses for any reason, its length included, is `KC_FAILED`. A blob that needs options to load, such as a policy, cannot be used. Use the key, and free it, in the thread that loaded it |
| `kc_key_cert(&k, der, len, e)` | an X.509 certificate, in DER, as an asymmetric key for `kc_pkey_query()` and `kc_pkey_verify()`: loaded into the keyring of the calling thread and used by its serial, as for `kc_key_blob()`. The kernel takes only certificates as asymmetric keys, and refuses what is not one, a key of an algorithm it lacks (an EC key, on a kernel without ECDSA), and a self-signed certificate whose signature does not hold: that is `KC_FAILED` with its `errno`; an empty certificate is `KC_USAGE`. It needs a kernel 4.20 or newer with `ASYMMETRIC_KEY_TYPE`, `ASYMMETRIC_PUBLIC_KEY_SUBTYPE`, `X509_CERTIFICATE_PARSER` and the algorithm of the key (`CRYPTO_RSA`). It does not check the signature of any other certificate, and nothing here says who made the key: trusting it is the caller's, as with a public key given to openssl. Use the key, and free it, in the thread that loaded it |
| `kc_key_pubkey(&k, spki, len, e)` | a public key, a DER SubjectPublicKeyInfo as `openssl pkey -pubout -outform DER` writes it, as an asymmetric key for `kc_pkey_query()` and `kc_pkey_verify()`. The kernel takes only certificates, so the key is wrapped in one that the kernel loads without checking its signature, which is no signature: its issuer (`CN=kcrypto issuer`) is not its subject (`CN=kcrypto`), so it is not self-signed, and it is valid from 1970 to 9999, since a board may boot with its clock anywhere. Then it is loaded as by `kc_key_cert()`, with the same requirements, failures and trust: the certificate adds nothing to the key, and says nothing of who made it. The certificate names an RSA signature, so the key is taken for RSA only: another key, such as an EC one, is refused at the loading or at the query, `KC_FAILED`. `KC_USAGE` when `spki` is not one DER SEQUENCE `len` bytes long, its length in DER's shortest form and in at most two bytes (`EINVAL`), such as a PEM file, or is longer than 16384 bytes (`E2BIG`) |
| `kc_key_unload(k, e)` | takes a key of `kc_key_blob()`, `kc_key_cert()` or `kc_key_pubkey()` out of the keyring at once, `KC_FAILED` when the kernel refuses; `KC_OK`, doing nothing, for any other key and for one already unloaded. `kc_key_free()` takes the key out too, if it is still there, but cannot say that it failed |
| `kc_key_serial(k)` | the serial of a keyring key, 0 for raw bytes |
| `kc_key_free(k)` | clears raw bytes and frees the key; a key of `kc_key_blob()`, `kc_key_cert()` or `kc_key_pubkey()` still loaded is taken out of the keyring first, in the thread that loaded it only, saying nothing of a failure |
| `kc_hash_open(&h, name, k, e)` | a hash or an HMAC, by the name of an algorithm or of a driver (check a driver chosen by name with `kc_driver_check()` first); `k` is NULL for an algorithm without a key, and can be freed once the hash is open; `KC_REFUSED` when the kernel has no such algorithm |
| `kc_hash_update(h, in, len, e)` | adds data, in as many calls as needed |
| `kc_hash_final(h, md, &md_len, e)` | gives the digest and ends the hash: `md_len` is the room in `md` on the way in, and the length of the digest on the way out; `KC_HASH_MAX` is always enough, and less room than the digest is `KC_USAGE`. After it, and after a call that fails, the hash can only be freed |
| `kc_hash_free(h)` | frees the hash |
| `kc_cipher_open(&c, name, k, encrypt, iv, iv_len, e)` | a block cipher in a mode whose IV is one block, such as CBC, by the name of an algorithm or of a driver, for encryption (`encrypt` not 0) or decryption, with the PKCS#7 padding, `KC_REFUSED` when the kernel has no such algorithm; `iv_len` is the block size too, at most `KC_BLOCK_MAX`, and `k` can be freed once the cipher is open |
| `kc_cipher_update(c, in, len, out, &out_len, e)` | takes any length and writes whole blocks into `out`, which needs room for `len + iv_len` bytes and must not overlap `in`, setting `out_len`; in decryption it holds the last block back |
| `kc_cipher_final(c, out, &out_len, e)` | writes the rest, at most `iv_len` bytes: in encryption the last block with its padding, a whole block of padding when the input is a multiple of the block; in decryption the last block without its padding, or `KC_REFUSED` when the length or the padding is wrong; with a wrong length it still writes the last whole block, so that every whole block of the ciphertext goes out, as with `openssl enc -d`, and `out_len` says so; in decryption `out_len` is 0 on any other failure. This is not an authentication: a wrong IV, or a ciphertext changed in the middle, decrypts without any error, and what was written up to a `KC_REFUSED`, by the refusing call too, is to be discarded. It ends the cipher: after it, and after a call that fails, the cipher can only be freed |
| `kc_cipher_free(c)` | clears and frees the cipher |
| `kc_pkey_query(k, params, &info, e)` | what an asymmetric keyring key can do with the parameters of `keyctl` (`params`, such as `enc=pkcs1 hash=sha256`): in `info`, the operations (`ops`, of `KC_PKEY_ENCRYPT`, `KC_PKEY_DECRYPT`, `KC_PKEY_SIGN` and `KC_PKEY_VERIFY`), the size of the key in bits (`key_size`) and the largest data, signature, encrypted and decrypted sizes in bytes (`max_data`, `max_sig`, `max_enc`, `max_dec`). `KC_FAILED` with the kernel's `errno` when it refuses the key or the parameters: an unknown `enc=` or `hash=`, a hash it does not have, a key that is not asymmetric; `KC_USAGE` (`EINVAL`) for a key that is not a keyring key, and for `params` or `info` NULL. The library sets the reserved fields of `info` to 0 |
| `kc_pkey_verify(k, params, digest, digest_len, sig, sig_len, e)` | checks the signature `sig` of `digest` with an asymmetric keyring key and the parameters of `keyctl`: `KC_OK` when it holds, `KC_REFUSED` ("verification failure") when it does not. The kernel says no with `EKEYREJECTED`, `EBADMSG` or `EINVAL`, and gives `EINVAL` for a call it does not take too, so the key is first queried with the same parameters: what the query refuses, a key that cannot verify (`EOPNOTSUPP`) and any other failure of the kernel are `KC_FAILED`, never a forged signature. A digest of 0 bytes or longer than the key takes (`max_data`, which for RSA is the size of the key, not that of a digest), and an empty signature, are `KC_USAGE`; a signature longer than the key's is `KC_REFUSED`. The kernel gets the digest only: compute it with the hash that `hash=` names, over the data that were signed, since a digest of another length is refused like a forged signature, and nothing binds the digest to the data but the caller |
| `kc_pbkdf2(hmac, pass, pass_len, salt, salt_len, iter, out, out_len, e)` | PBKDF2 (RFC 8018) over an HMAC by the name of the algorithm, such as `hmac(sha256)`, or of a driver of one, `KC_REFUSED` when the kernel has no such HMAC, `KC_FAILED` (`ENOSYS`) for a hash that is not an HMAC, such as `sha256`: `out_len` bytes into `out`; `iter` and `out_len` are at least 1 |
| `kc_openssl_header(buf, len, salt, e)` | the salt of the header that `openssl enc` writes before what it encrypts with a passphrase and a random salt, `Salted__` and 8 bytes, from the first `KC_OPENSSL_HEADER_LEN` bytes of the stream; `KC_REFUSED` when they do not start with `Salted__`, or when `len`, what the stream had, is shorter |
| `kc_openssl_header_make(buf, salt)` | writes such a header |
| `kc_openssl_derive(hmac, pass, pass_len, salt, iter, key_len, &k, iv, iv_len, e)` | the key and the IV that `openssl enc -pbkdf2` derives from a passphrase and the salt of its header: PBKDF2 over `hmac` (`hmac(sha256)` is openssl's default) with `iter` iterations (10000 is openssl's default), `key_len` bytes of key first, as a key of raw bytes in `k`, then `iv_len` bytes of IV in `iv`. `key_len` is 1 to `KC_OPENSSL_KEY_MAX` (64, more than any cipher of `openssl enc` takes), `iv_len` at most `KC_BLOCK_MAX`, 0 for a mode without an IV, `iter` at least 1, else `KC_USAGE` (`EINVAL`); `KC_REFUSED` when the kernel has no such HMAC. The bytes it derives are cleared once the key is made; `k` is NULL after a failure |

With these, a signature of `openssl dgst -sha256 -sign` over RSA is checked by loading the public key with `kc_key_pubkey()`, or its certificate with `kc_key_cert()`, computing the digest of the data with `kc_hash_open()` on `sha256`, and verifying with `kc_pkey_verify()` and `enc=pkcs1 hash=sha256`.

With these, a file of `openssl enc -pbkdf2` is decrypted by reading the salt with `kc_openssl_header()`, deriving the key and the IV with `kc_openssl_derive()`, and decrypting the rest of the file with them.

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
