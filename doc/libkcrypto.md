# libkcrypto

`libkcrypto.so.0` gives user space the cryptography of the Linux kernel, with the keys where the kernel keeps them, in place of OpenSSL's `libcrypto`, which holds its keys in the program's memory. crypto-afalg moves onto it a part at a time; craf still uses [libafalg](libafalg.md). The library prints nothing and never exits: what to say about a failure, and what to do then, is the caller's.

Today it reaches the kernel through `AF_ALG`, its only backend. The interface is made of keys, algorithms and drivers, not of sockets, so that a backend added later changes nothing for its users; the type names (`skcipher`, `hash`) and the messages still come from `AF_ALG`.

## Stability

The interface, declared in `kcrypto.h`, is **unstable until version 1.0**. Its soname stays `libkcrypto.so.0` meanwhile, so a change does not stop an older program from loading a newer library: rebuild the programs linked against it whenever you update it. The exception is `struct kc_error`, which the caller allocates: a change of its size, `KC_MSG_MAX` included, changes the soname, even before 1.0.

## Building and linking

`make` builds `libkcrypto.so.0` together with the tools, and `make install` installs it with its link-time name `libkcrypto.so` and the header `kcrypto.h` (see "How to Install" in the README). Compile a program with `#include <kcrypto.h>` and link it with `-lkcrypto` against an installed copy: the build directory holds no `libkcrypto.so`. Like the rest of the project, the library is licensed under the GNU GPL v3.0 or later.

## Errors

Every function that can fail returns one of four statuses and, when its last argument, a `struct kc_error *`, is not NULL, fills it in with the same status, the `errno` of the cause (0 when there is none) and a message:

| status | meaning |
|---|---|
| `KC_OK` (0) | done |
| `KC_REFUSED` (1) | the answer is no: the kernel has no such algorithm, `/proc/crypto` lists no such driver |
| `KC_USAGE` (2) | an argument is wrong: an unknown type, a name too long |
| `KC_FAILED` (3) | it could not be done: a socket that does not open, `/proc/crypto` that cannot be read |

`KC_REFUSED` and `KC_FAILED` are kept apart on purpose: a "no" is an answer, a failure is the lack of one.

## Functions

| function | what it does |
|---|---|
| `kc_algo_available(type, name, e)` | asks the kernel whether it has an algorithm or a driver by its exact name (`type` is `skcipher` or `hash`): `KC_REFUSED` is its no, `KC_FAILED` no answer; the kernel builds an algorithm made from a template, such as `hmac(sha256)`, when asked, and may load a module |
| `kc_driver_check(type, driver, algo, e)` | checks that `/proc/crypto` lists `driver` as a driver of `algo` of a type a `type` socket takes (`skcipher` and `lskcipher` for `skcipher`, and the `blkcipher`, `ablkcipher` and `givcipher` of the kernels before 5.5; `ahash` and `shash` for `hash`); the kernel takes a driver of another algorithm without any error, so a driver chosen by name needs this check. `KC_REFUSED` when it is not listed so, `KC_FAILED` only when `/proc/crypto` cannot be read. It does not ask the kernel, so a driver the kernel builds from a template is listed only once something has used it since the boot; `kc_algo_available()` on its name builds it |
