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

  * A Linux system with `AF_ALG` support enabled; keys from the keyring (`-S|--keyserial`) need **Kernel 6.2 or newer** with `KEYS` support.
  * A C compiler (e.g., `gcc`).
  * The standard Linux kernel headers installed on your system.
  * The keyutils library and its header `keyutils.h` (e.g., the `libkeyutils-dev` package).
  * git, used by the build to compute the version string.
  * bash, for the version helper and the tests.
  * GNU make 4.2 or newer (for `.SHELLSTATUS`).

## How to Build

Navigate to the project directory and use `make` to compile the application.

```bash
$ git clone https://github.com/giometti/crypto-afalg.git
$ cd crypto-afalg
$ make
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

If a test is marked as `Skipped`, it means that your machine does not support the corresponding crypto algorithm.

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
      - a symbolic name as [<keyring>,]<type>,<name>
```

Note that, if your system does not support symmetric encryption via keyring keys (see the define `ALG_SET_KEY_BY_KEY_SERIAL`), the `-S|--keyserial` option will not be shown.

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
      - a symbolic name as [<keyring>,]<type>,<name>
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

By using the `--force-driver` option, you can force the use of a specific kernel driver of an algorithm despite its priority (see `/proc/crypto`).

-----

## License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**. You can find the full text of the license in the `LICENSE` file in this repository or by visiting the [official GNU website](https://www.gnu.org/licenses/gpl-3.0.html).
