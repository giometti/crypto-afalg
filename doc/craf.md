# craf

`craf` seals a stream into a single-file archive encrypted with AES-256-CBC, and unseals it. The cipher runs in the kernel, through [libkcrypto](libkcrypto.md) and `AF_ALG`, with a key taken from the keyring by serial, or loaded from the blob of a trusted key that the archive carries: either way the key does not pass through craf's memory. craf therefore needs a kernel 6.2 or newer with `KEYS`, and a libkcrypto that takes keyring keys (see `kc_key_serial_supported()`; crypto-afalg shows `-S|--keyserial` in its help exactly when it does): without them every seal and unseal exits with status 3.

```bash
$ craf seal -cipher-driver cbc-aes-ce -enc-key @s,user,backup < data.tar > data.craf
$ craf unseal -enc-key @s,user,backup < data.craf > data.tar
$ craf seal -cipher-driver cbc-aes-ce -enc-blob key.blob < data.tar > data.craf
$ craf unseal < data.craf > data.tar
```

  * `-in <file>`, `-out <file>`: read and write files instead of stdin and stdout. `-out` is written as stdout would be: it is truncated once the options are checked and the input is open, and kept whatever the exit status, so an error found in the options, in the archive's header (a key option it does not take included) or in loading the key leaves it empty, and one found while decrypting leaves what was written before it: with a wrong padding every block but the last, with a wrong length every whole block (up to v1.3.0, every whole block but the last), as `openssl enc -d` does. The input and the output cannot be the same regular file, nor can the output be the `-enc-blob` file.
  * `-cipher-driver <driver>` (seal): the kernel driver of `cbc(aes)` to encrypt with, by its exact name (see `/proc/crypto`), at most 63 characters. The name of an algorithm, or a driver of another algorithm, is a wrong usage.
  * `-cipher-algo cbc(aes)` (seal): let craf choose the driver, the one of highest priority among the tested, not internal drivers of `cbc(aes)` in `/proc/crypto`, the first listed among equals: the rule of the kernel's own choice, as its sources state it (`__crypto_alg_lookup()`). Give either `-cipher-driver` or `-cipher-algo`. Some drivers that the kernel prefers cannot be used through `AF_ALG` (on i.MX, `cbc-aes-tee`): there, name the driver.
  * The driver that encrypted is written in the archive, and unseal uses the same one, only if `/proc/crypto` already lists it as a driver of the archive's algorithm: craf binds no driver an archive names before that check, so an archive cannot make the kernel build one. A driver the kernel builds from a template, such as `cbc(aes-generic)`, is listed only once something has used it since the boot. A driver the archive names and `/proc/crypto` does not list makes unseal exit with status 3; one it lists for another algorithm means the header is false, status 1. Either way, one of these takes the place of the archive's driver:
    * `-cipher-driver <driver>` (unseal): a driver named on the command line, checked as for seal;
    * `-any-driver` (unseal): the one `-cipher-algo` would choose.
  * `-enc-key <key>` (seal, and unseal of an archive sealed with it): the key, of 32 bytes, a serial number or `[<keyring>,]<type>,<description>` as for crypto-afalg `-S`. With two commas the first field is the keyring, so a description with a comma needs the keyring: `user,a,b` is the key of type `a` and description `b` in `@u`. A description that more than one key holds is refused, among the keyrings craf can read. craf checks the length of a `user` key only; for any other type, such as `logon` or `trusted`, creating it with 32 bytes is up to you.
  * `-enc-blob <file>` (seal): the blob of a trusted key, in hex as `keyctl pipe` writes it (a final newline, as `keyctl print` writes it, is accepted), at most 65535 bytes. craf loads it into the keyring of its own thread, which no other process can search and which goes with the process, encrypts with that key, writes the blob into the archive and removes the key; unseal of that archive takes no key option, and loads the blob from the archive in the same way. The blob loads only where a trust source holds the key that sealed it (a TPM, a TEE such as OP-TEE, CAAM): what that means for the archives is below, with what they protect. It needs a kernel with trusted keys (`TRUSTED_KEYS`) that its `AF_ALG` can reach (trusted keys built in, or both as modules; otherwise setting the key fails with "Protocol not available"), and a trust source. A blob that needs options to load, such as a policy or a password, cannot be used. A trusted key is of 32 to 128 bytes and AES takes 32 at most, so make it of 32 (`keyctl add trusted <name> "new 32" ...`): a longer one makes seal exit with status 3. Give either `-enc-key` or `-enc-blob`, and write options in full: an abbreviation such as `-enc` names more than one.

The exit status is:

  * 0 when the work is done;
  * 1 when the archive is refused: its format (also a driver it names that `/proc/crypto` lists for another algorithm), a truncation, `bad decrypt`;
  * 2 for a wrong usage, also a `-cipher-driver` that is not a driver of `cbc(aes)`, a malformed or ambiguous `-enc-key`, a `user` key that is not of 32 bytes, `-enc-key` and `-enc-blob` together or neither for seal, `-enc-key` missing for an archive sealed with it or given for one that carries its key, an `-enc-blob` file that is empty, not a blob in hex or longer than 65535 bytes, or a `-out` that is the `-enc-blob` file;
  * 3 when craf could not do it: a driver or a key that is not there, a driver in the archive that `/proc/crypto` does not list, an archive of a newer version or with a key source this craf does not know (it may be good: a newer craf can read it), `/proc/crypto` unreadable, an input or output error, an `-enc-blob` file that cannot be read, a blob the kernel does not load (an archive of another system, a blob that was changed, a kernel without trusted keys or without a trust source up, a blob that needs options to load), a trusted key that `AF_ALG` cannot use (trusted keys it cannot reach, a key longer than 32 bytes).

**The output is valid only with exit status 0**: unseal writes the data as it decrypts them and checks the padding at the end, so whatever it wrote before a refusal must be discarded. In a pipe, craf sees only the end of its input: a script checks the status of every command of the pipe (`set -o pipefail`), for example of the `tar` that feeds seal.

The archives of this version are encrypted, not authenticated. craf refuses a header it does not understand, an archive cut to a length that is not one of an archive, and almost always a wrong key or an archive cut by whole blocks, through the padding. The data stay secret from whoever does not have the key only as long as nobody can make unseal run on archives they have changed and see how it ends: the padding check then tells, archive after archive, something of the content. Without the key, a change to the encrypted data or to the IV goes undetected, decrypts to data changed where the change chose (a change to the IV alters the first block exactly, nothing else) with exit status 0, unless it reaches the padding; so unseal should not run on its own on archives from media that others can write. craf does not detect the replay of an older archive sealed with the same key, and it cannot protect against somebody who can use the key, for example root on the running system. An archive sealed with `-enc-blob` carries its key as a blob that any program on the system can have the trust source load, with no privilege and without craf: there, whoever can read the archive can decrypt it, and whoever can load a blob can make an archive of their own content that unseal takes with exit status 0; on that system only the read permissions of the archives and of the blob file protect them, not those of craf. Such an archive opens only where a trust source holds the key that sealed its blob: with a trust source that has a key of its own (a provisioned TPM, an OP-TEE with a hardware unique key, a closed CAAM) that is this system only, and no longer once that state changes (a TPM cleared or its parent key removed, an update of the trust source that changes how it derives its keys), so keep the archives you may need openable across such changes, or seal them again before; with one in a development state (an OP-TEE with the default unique key, a CAAM not closed) it is every system of that kind. Authentication will come with version 2 of the format, and craf will still unseal the archives of version 1.

The archive format, version 1, integers little-endian, a string being its length in one byte, 1 to 255, followed by as many characters from 0x21 to 0x7e (printable ASCII without the space):

| field | size | value |
|---|---|---|
| `magic` | 8 | `AFALGARC` |
| `version` | 2 | 1 |
| `hdr_len` | 2 | the length of the whole header |
| `cipher_driver` | string | the driver that encrypted |
| `cipher_algo` | string | `cbc(aes)` |
| `key_len` | 1 | 32 |
| `key_source` | string | `serial`: the key is the caller's; `trusted`: the key is the blob that follows |
| `iv` | 16 | random |
| fields of the key source | | none for `serial`; for `trusted`, `blob`: its length in 2 bytes, at least 1 (the header ends with it, so at most 65535 less the rest of the header), then the bytes of the blob as the kernel gives it (`keyctl pipe`, decoded from hex) |
| data, from `hdr_len` | n x 16 | AES-256-CBC of the input with PKCS#7 padding |

The first 12 bytes, `magic`, `version` and `hdr_len`, keep their place in every version, so that a reader tells an archive of another version from something else.

The tests of craf need `keyctl`, `openssl` and `cbc(aes)` in the kernel; without them they are `Skipped`. They use the driver `-cipher-algo` chooses, or the one `CRAF_TEST_DRIVER` names, for a kernel whose preferred driver cannot be used through `AF_ALG`. The test that seals with a trusted key (`[trusted]`) creates one with the options of `new` in `CRAF_TEST_TRUSTED` (on a TPM 2.0 the parent key, for example `keyhandle=0x81000001`): without the variable it is `Skipped`, with the reason, where the key cannot be created; with it, a key that cannot be created is a failure. libkcrypto's test of trusted key blobs (`[blob-trusted]`) takes the same variable, in the same way.

## Known bugs

  * Until the archives are authenticated, a wrong key can, rarely (about once in 256 tries), give exit status 0 and garbage as output, since the padding is the only check it can fail.
