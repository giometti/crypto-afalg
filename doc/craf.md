# craf

`craf` seals a stream into a single-file archive encrypted with AES-256-CBC, and unseals it. The cipher runs in the kernel through `AF_ALG`, with a key taken from the keyring by serial, so the key does not pass through craf's memory. craf therefore needs a kernel 6.2 or newer with `KEYS`, and a build with `ALG_SET_KEY_BY_KEY_SERIAL`: without them every seal and unseal exits with status 3.

```bash
$ craf seal -cipher-driver cbc-aes-ce -enc-key @s,user,backup < data.tar > data.craf
$ craf unseal -enc-key @s,user,backup < data.craf > data.tar
```

  * `-in <file>`, `-out <file>`: read and write files instead of stdin and stdout. `-out` is written as stdout would be: it is truncated once the options and the input are accepted, and kept whatever the exit status. The input and the output cannot be the same regular file.
  * `-cipher-driver <driver>` (seal): the kernel driver of `cbc(aes)` to encrypt with, by its exact name (see `/proc/crypto`), at most 63 characters. The name of an algorithm, or a driver of another algorithm, is a wrong usage.
  * `-cipher-algo cbc(aes)` (seal): let craf choose the driver, the one of highest priority among the tested, not internal drivers of `cbc(aes)` in `/proc/crypto`, the first listed among equals: the rule of the kernel's own choice, as its sources state it (`__crypto_alg_lookup()`). Give either `-cipher-driver` or `-cipher-algo`. Some drivers that the kernel prefers cannot be used through `AF_ALG` (on i.MX, `cbc-aes-tee`): there, name the driver.
  * The driver that encrypted is written in the archive, and unseal uses the same one, only if `/proc/crypto` already lists it as a driver of the archive's algorithm: craf binds no driver an archive names before that check, so an archive cannot make the kernel build one. A driver the kernel builds from a template, such as `cbc(aes-generic)`, is listed only once something has used it since the boot. A driver the archive names and `/proc/crypto` does not list makes unseal exit with status 3; one it lists for another algorithm means the header is false, status 1. Either way, one of these takes the place of the archive's driver:
    * `-cipher-driver <driver>` (unseal): a driver named on the command line, checked as for seal;
    * `-any-driver` (unseal): the one `-cipher-algo` would choose.
  * `-enc-key <key>` (required): the key, of 32 bytes, a serial number or `[<keyring>,]<type>,<description>` as for crypto-afalg `-S`. With two commas the first field is the keyring, so a description with a comma needs the keyring: `user,a,b` is the key of type `a` and description `b` in `@u`. A description that more than one key holds is refused, among the keyrings craf can read. craf checks the length of a `user` key only; for any other type, such as `logon` or `trusted`, creating it with 32 bytes is up to you.

The exit status is:

  * 0 when the work is done;
  * 1 when the archive is refused: its format (also a driver it names that `/proc/crypto` lists for another algorithm), a truncation, `bad decrypt`;
  * 2 for a wrong usage, also a `-cipher-driver` that is not a driver of `cbc(aes)`, a malformed or ambiguous `-enc-key`, or a `user` key that is not of 32 bytes;
  * 3 when craf could not do it: a driver or a key that is not there, a driver in the archive that `/proc/crypto` does not list, an archive of a newer version or with a key source this craf does not know (it may be good: a newer craf can read it), `/proc/crypto` unreadable, an input or output error.

**The output is valid only with exit status 0**: unseal writes the data as it decrypts them and checks the padding at the end, so whatever it wrote before a refusal must be discarded. In a pipe, craf sees only the end of its input: a script checks the status of every command of the pipe (`set -o pipefail`), for example of the `tar` that feeds seal.

The archives of this version are encrypted, not authenticated. craf refuses a header it does not understand, an archive cut to a length that is not one of an archive, and almost always a wrong key or an archive cut by whole blocks, through the padding. The data stay secret from whoever does not have the key only as long as nobody can make unseal run on archives they have changed and see how it ends: the padding check then tells, archive after archive, something of the content. Without the key, a change to the encrypted data or to the IV goes undetected, decrypts to data changed where the change chose (a change to the IV alters the first block exactly, nothing else) with exit status 0, unless it reaches the padding; so unseal should not run on its own on archives from media that others can write. craf does not detect the replay of an older archive sealed with the same key, and it cannot protect against somebody who can use the key, for example root on the running system. Authentication will come with version 2 of the format, and craf will still unseal the archives of version 1.

The archive format, version 1, integers little-endian, a string being its length in one byte, 1 to 255, followed by as many characters from 0x21 to 0x7e (printable ASCII without the space):

| field | size | value |
|---|---|---|
| `magic` | 8 | `AFALGARC` |
| `version` | 2 | 1 |
| `hdr_len` | 2 | the length of the whole header |
| `cipher_driver` | string | the driver that encrypted |
| `cipher_algo` | string | `cbc(aes)` |
| `key_len` | 1 | 32 |
| `key_source` | string | `serial`: the key is the caller's |
| `iv` | 16 | random |
| fields of the key source | | none for `serial` |
| data, from `hdr_len` | n x 16 | AES-256-CBC of the input with PKCS#7 padding |

The first 12 bytes, `magic`, `version` and `hdr_len`, keep their place in every version, so that a reader tells an archive of another version from something else.

The tests of craf need `keyctl`, `openssl` and `cbc(aes)` in the kernel; without them they are `Skipped`. They use the driver `-cipher-algo` chooses, or the one `CRAF_TEST_DRIVER` names, for a kernel whose preferred driver cannot be used through `AF_ALG`.

## Known bugs

  * Until the archives are authenticated, a wrong key can, rarely (about once in 256 tries), give exit status 0 and garbage as output, since the padding is the only check it can fail.
