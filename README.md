# crypto-afalg

A user-space application that leverages the Linux Kernel Crypto API through the `AF_ALG` socket family.

This project provides a simple and efficient way to offload cryptographic operations directly to the kernel, taking advantage of hardware acceleration where available, and the possibility to use keys from the Linux Keyring system.

-----

## About

The Linux kernel includes a powerful Crypto API that allows various components to perform cryptographic tasks. The `AF_ALG` (Address Family for Algorithms) socket family provides a clean and secure user-space interface to this API.

This project demonstrates how to use this interface to perform common cryptographic operations with the help of keys from the Linux Keyring system.

The main advantage of using the `AF_ALG` interface is **security**: cryptographic operations are handled within the kernel and, with keys from the Linux Keyring (`-S|--keyserial`), crypto-afalg never holds the key in its memory; how well the key itself is protected depends on its type (`trusted` and `logon` keys cannot be read from user space, `user` keys can).

A secondary advantage is **performance**: there is potential for significant speed improvements by utilizing hardware cryptographic accelerators (e.g., AES-NI, CAAM).

## Features

This project provides a basic example of how to interact with the kernel's crypto API. The current implementation demonstrates:

  * **Hashing:** Calculating message digests using algorithms available in the kernel.
  * **Symmetric Ciphers:** Performing encryption and decryption with standard ciphers.

*(Note: The list of supported algorithms depends on your Linux kernel configuration.)*

## Requirements

To build and run this project, you need:

  * A Linux system with `AF_ALG` support enabled; keys from the keyring (`-S|--keyserial`, and craf always) need **Kernel 6.2 or newer** with `KEYS` support.
  * A C compiler (e.g., `gcc`).
  * The standard Linux kernel headers installed on your system.
  * The keyutils library and its header `keyutils.h` (e.g., the `libkeyutils-dev` package).
  * git, used by the build to compute the version string.
  * bash, for the version helper and the tests.
  * binutils (`readelf`, `nm`), for the tests.
  * keyctl (keyutils) and openssl, for the tests.
  * GNU make 4.2 or newer (for `.SHELLSTATUS`).

## How to Build

Navigate to the project directory and use `make` to compile the application.

```bash
$ git clone https://github.com/giometti/crypto-afalg.git
$ cd crypto-afalg
$ make
```

The build produces the tools, `crypto-afalg` and `craf`, and the shared libraries they use, `libkcrypto.so.0` (see [libkcrypto](#libkcrypto)) and `libafalg.so.0` (see [libafalg](#libafalg)). To run the tools from the build directory without installing them, tell the dynamic loader where the libraries are:

```bash
$ export LD_LIBRARY_PATH=$PWD
```

The version string is stamped into the binary at build time by `tools/git-version.sh`, from `git describe --tags --long --match "v*" --dirty` (for example `v1.0.0-14-g93990b9`, with a trailing `-dirty` for a modified tree). A repository without `v*` tags gives `v0.0.0-<commits>-g<hash>`, and a source tree outside any git repository of its own gives `v0.0.0-0-g0000000`, meaning "no version specified". The build stops with an error if the string does not match that format or cannot be determined (for example, git is not installed).

You can run tests using the `make tests` command:

```bash
$ make tests
executing test0001.sh... aes-128-cbc [simple-enc-dec]: OK.
executing test0002.sh... aes-128-cbc [long-enc-dec]: OK.
executing test0003.sh... aes-128-cbc [file-enc-dec]: OK.
... (truncated output) ...
all tests are OK!
```

To catch memory errors that do not change the output, run the tests with AddressSanitizer: `make tests ASAN=1` builds the tools and the libraries with `-fsanitize=address` (gcc and clang have it), and a test fails when AddressSanitizer reports an error. `make ASAN=1` builds them the same way.

If a test is marked as `Skipped`, it means that your machine does not support the corresponding crypto algorithm, or lacks something else the test needs (for craf, see below).

The tests of craf, of `--force-driver` and of libkcrypto use the driver of `cbc(aes)` that the kernel prefers, the one `craf seal -cipher-algo` chooses. On a kernel whose preferred driver cannot be used through `AF_ALG`, name a usable one in `CRAF_TEST_DRIVER`, for example `make tests CRAF_TEST_DRIVER=cbc-aes-ce`; the tests of `--force-driver` and of libkcrypto check it first, and a driver the kernel does not have, or one that is not of `cbc(aes)`, makes them fail instead of being `Skipped`. The test that seals with a trusted key (`[trusted]`) creates one with the options of `new` in `CRAF_TEST_TRUSTED`: on a TPM 2.0 the parent key, for example `make tests CRAF_TEST_TRUSTED=keyhandle=0x81000001`. Without the variable it is `Skipped`, with the reason, where the key cannot be created; with it, a key that cannot be created is a failure.

## How to Install

```bash
$ make install
```

installs `crypto-afalg` and `craf` into `PREFIX` (default `/usr/bin`), the libraries `libkcrypto.so.0` and `libafalg.so.0` and their link-time names `libkcrypto.so` and `libafalg.so` into `LIBDIR` (default `/usr/lib`), and the headers `kcrypto.h` and `afalg.h` into `INCLUDEDIR` (default `/usr/include`); `DESTDIR`, if set, is prepended to all three, for packaging. `make uninstall` removes the same files.

`LIBDIR` must be a directory the dynamic loader searches: after installing into one it finds only through its cache, such as `/usr/local/lib`, run `ldconfig` as root.

## How to Use

The `crypto-afalg` tool is a command-line utility.

### Basic Usage

To check the version of the tool:

```bash
$ ./crypto-afalg --version
crypto-afalg v0.0.0-0-g0000000
Copyright (C) 2025 Rodolfo Giometti <giometti@enneenne.com>
This is free software, and you are welcome to redistribute it under
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or any later version.
*** This program comes with ABSOLUTELY NO WARRANTY. ***
```

To view the general help message with a list of available commands:

```bash
$ ./crypto-afalg --help
usage: crypto-afalg [ -d|--debug ] [ -h|--help ] [ --version ] [ --force-driver <name> ] <command> ...
  <command> can be:
    encrypt <algo> <opts> : encrypt data
    decrypt <algo> <opts> : decrypt data
    hash <algo> <opts>    : compute data hash
```

### Encryption and Decryption

For detailed help on the `encrypt` or `decrypt` commands:

```bash
$ ./crypto-afalg encrypt --help
to see available algos use:
	crypto-afalg encrypt
to check a kernel algo use:
	crypto-afalg encrypt check-kalgo <kname>
to get help use:
	crypto-afalg encrypt help|-h|--help
normal usage:
	crypto-afalg encrypt <algo> <KEY> <IV> | <PASS> [ <SALT> ] [ -i|--iterations <val> ]
where <KEY> can be one of:
    -K|--key <val>          : hex value key
    -k|--keyfile <name>     : key from file
    -S|--keyserial <val>    : key from keyring
where <IV> can be one of:
    -V|--iv <val>           : hex value iv
    -v|--ivfile <name>      : iv from file
where <PASS> can be one of:
    -P|--pass <str>         : passkey
    -p|--passfile <name>    : passkey from file
where <SALT> can be one of:
    -T|--salt <val>         : hex value salt
    -t|--saltfile <name>    : salt from file
NOTE: keyring key can be:
      - a simple serial number, or
      - a symbolic name as [<keyring>,]<type>,<name>, with
        <keyring> @u (user, the default) or @s (session)
```

Note that, if your system does not support symmetric encryption via keyring keys (see the define `ALG_SET_KEY_BY_KEY_SERIAL`), the `-S|--keyserial` option will not be shown.

A serial is a positive decimal number, digits only. The keyring of a symbolic name is `@u` (also `user`, the default) or `@s` (also `session`), named exactly; with two commas the first field is the keyring, so a description with a comma needs the keyring (`user,a,b` is the key of type `a` and description `b` in `@u`). The search for a symbolic name also looks into the keyrings linked to the one named, and a description that two keys hold there is refused instead of taking the first found; a key in a keyring that you can search but not read is not counted. Up to v1.1.0 crypto-afalg accepted a serial followed by other characters, a negative or too large one, a prefix of a keyring name, and took the first of two keys with the same description: such specs are now refused.

To encrypt/decrypt data:

```bash
$ ./crypto-afalg encrypt aes-128-cbc \
    -K 06a9214036b8a15b512e03d534120006 \
    -V 3dafba429d9eb430b422da802c9fac41 < file.txt > file.enc

$ ./crypto-afalg decrypt aes-128-cbc \
    -K 06a9214036b8a15b512e03d534120006 \
    -V 3dafba429d9eb430b422da802c9fac41 < file.enc > file.txt
```

`decrypt` checks only the length and the padding of the ciphertext: a truncated ciphertext, and almost always a wrong key, make it print `bad decrypt` and exit with status 1; a read or write error also exits with status 1, with its own message. Data already written to the output before an error must be discarded: check the exit status, not the output. This is not an authentication: a wrong IV or a corrupted ciphertext usually decrypts, without any error, to partly wrong data.

Encrypted files are OpenSSL compatible (except with `caam(aes-256-cbc)`, whose key is a CAAM tagged key), so you can test them like this:

```bash
$ echo 'Test data' | ./crypto-afalg encrypt aes-128-cbc \
    -K 06a9214036b8a15b512e03d534120006 \
    -V 3dafba429d9eb430b422da802c9fac41 | \
  openssl enc -aes-128-cbc -d \
    -K 06a9214036b8a15b512e03d534120006 \
    -iv 3dafba429d9eb430b422da802c9fac41
Test data
```

You can also use a passphrase:

```bash
$ echo 'Test data' | ./crypto-afalg encrypt aes-128-cbc -P 'test-phrase' | \
  openssl enc -aes-128-cbc -d -pbkdf2 -k 'test-phrase'
Test data
```

### Hashing

To get detailed help and usage examples for the `hash` command:

```bash
$ ./crypto-afalg hash --help
to see available algos use:
	crypto-afalg hash
to check a kernel algo use:
	crypto-afalg hash check-kalgo <kname>
to get help use:
	crypto-afalg hash help|-h|--help
normal usage:
	crypto-afalg hash <algo> <KEY>
where <KEY> can be one of:
    -K|--key <val>          : hex value key
    -k|--keyfile <name>     : key from file
    -S|--keyserial <val>    : key from keyring
    -P|--pass <str>         : passkey
    -p|--passfile <name>    : passkey from file
NOTE: keyring key can be:
      - a simple serial number, or
      - a symbolic name as [<keyring>,]<type>,<name>, with
        <keyring> @u (user, the default) or @s (session)
```

To hash data:

```bash
$ echo 'Single block msgSecond block msg' | \
  ./crypto-afalg hash sha-256
0acbb46a235c5a2b49f4de5e469b5d9964b4a470cb071312a0ae72dbb21d9e9d
```

The output is the same as that of other hashing tools:

```bash
$ echo 'Single block msgSecond block msg' | \
  sha256sum
0acbb46a235c5a2b49f4de5e469b5d9964b4a470cb071312a0ae72dbb21d9e9d  -
```

An error the kernel reports while hashing stops the command with its message and exit status 1. Up to v1.3.0 it went unnoticed: crypto-afalg printed whatever its buffer held, with exit status 0.

### Common Commands

You can list available algorithms:

```bash
$ ./crypto-afalg decrypt
crypto-afalg:   name                kernel-name    block(B)   key/iv(B)
crypto-afalg: - aes-128-cbc         cbc(aes)          16        16/16
crypto-afalg: - aes-256-cbc         cbc(aes)          16        32/16
crypto-afalg: - caam(aes-256-cbc)   tk(cbc(aes))      16        52/16
crypto-afalg:   NOTE: 'x' means 'not available'
```

or

```bash
$ ./crypto-afalg hash
crypto-afalg:   name                kernel-name    block(B)   key(B)
crypto-afalg: - sha-256             sha256            64        0
crypto-afalg: - hmac-sha-256        hmac(sha256)      64        32
crypto-afalg:   NOTE: 'x' means 'not available'
crypto-afalg:   NOTE: algo with key(B) > 0 requires a key
```

An algorithm is available when the kernel gives an `AF_ALG` socket for it: the list, `check-kalgo` (for the kernel names of the list) and every command without `--force-driver` ask the kernel with a `bind()`, not `/proc/crypto`, since an algorithm the kernel builds from a template, such as `hmac(sha256)`, is listed there only once something has used it since the boot. Asking counts as a use: it builds the template, and may make the kernel load a module.

By using the `--force-driver` option, you can force the use of a specific kernel driver of an algorithm despite its priority (see `/proc/crypto`). The driver must be listed in `/proc/crypto` as one of that algorithm, with a type that a socket of that kind takes (`skcipher` or `lskcipher` for a cipher, and the `blkcipher`, `ablkcipher` and `givcipher` of the kernels before 5.5; `ahash` or `shash` for a hash), so a driver the kernel builds from a template is refused until something has used it since the boot. Up to v1.3.0 the type of a driver forced for a cipher was not checked.

## libkcrypto

`libkcrypto.so.0` gives user space the cryptography of the Linux kernel, with the keys where the kernel keeps them; crypto-afalg moves onto it a part at a time. Its interface is **unstable until version 1.0**; what it offers and how to use it are in [doc/libkcrypto.md](doc/libkcrypto.md).

## libafalg

`libafalg.so.0` is the `AF_ALG` socket layer that craf, and crypto-afalg for what has not moved to libkcrypto yet, use, as a shared library for other tools too. Its interface is **unstable until version 1.0**; what it offers and how to use it are in [doc/libafalg.md](doc/libafalg.md).

## craf

`craf` seals a stream into a single-file archive encrypted with AES-256-CBC, and unseals it, with a key from the keyring or from the blob of a trusted key that the archive then carries:

```bash
$ craf seal -cipher-driver cbc-aes-ce -enc-key @s,user,backup < data.tar > data.craf
$ craf unseal -enc-key @s,user,backup < data.craf > data.tar
$ craf seal -cipher-driver cbc-aes-ce -enc-blob key.blob < data.tar > data.craf
$ craf unseal < data.craf > data.tar
```

Its options, exit statuses, what it protects against, the archive format and its known bugs are in [doc/craf.md](doc/craf.md).

-----

## License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**. You can find the full text of the license in the `LICENSE` file in this repository or by visiting the [official GNU website](https://www.gnu.org/licenses/gpl-3.0.html).
