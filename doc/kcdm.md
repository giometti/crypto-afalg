# kcdm

`kcdm` opens and closes a dm-crypt device whose key is in the keyring, as `cryptsetup open --type plain` and `cryptsetup close` do, but with no UUID, and without `libdevmapper` or udev: it maps a whole block device to `/dev/mapper/<name>` through the `crypt` target of device-mapper, which [libkcrypto](libkcrypto.md) sets up with the ioctls of `/dev/mapper/control`. The key never passes through kcdm's memory: the table names it by its type and description, and dm-crypt takes it from the keyring. kcdm is meant for an initramfs, where it takes the place of `dmsetup create`, `dmsetup mknodes` and `dmsetup remove` for such a device; it does nothing else of what `dmsetup` does.

```bash
$ kcdm open /dev/mmcblk0p3 root -cipher capi:cbc-aes-tee-plain -key @u,trusted,logon -key-size 32
$ kcdm open /dev/mmcblk0p3 root -cipher 'capi:tk(cbc(aes))-plain' -key @u,logon,logkey: -key-size 36 -opt sector_size:512
$ kcdm close root
```

The first line makes the same device as `dmsetup create root --table "0 <sectors> crypt capi:cbc-aes-tee-plain :32:trusted:logon 0 /dev/mmcblk0p3 0"` followed by `dmsetup mknodes root`, and the last one does what `dmsetup remove root` does.

## Command line

`kcdm -help` (or `help`) prints the usage, `kcdm -version` (or `version`) the version; `-help` after `open` or `close`, and among the options of `open`, prints the usage too, and exits with status 0. The device and the name of `open` come first, then the options, which are written with one dash, as craf's (two are accepted too), an abbreviation that names one option only (`-key-s` for `-key-size`) and the form `-opt=<value>` included; none can be given twice but `-opt`. A device or a name starting with a dash is refused by `open`, since it would be read as an option. kcdm needs `libkcrypto.so.0` and `libkeyutils` at run time.

## open

`kcdm open <device> <name> -cipher <cipher> -key <key> -key-size <bytes> [-opt <parameter>]...`

  * `<device>`: the block device to map, as a whole; its size, in sectors of 512 bytes, is the length of the mapping, rounded down. It goes into the table by its device number, so its path can be any. kcdm opens it for itself alone (`O_EXCL`) to measure it, so a device that is mounted, or mapped already, under this name or another, is refused.
  * `<name>`: the name of the device, and of its node `/dev/mapper/<name>`: 1 to 127 bytes, and not `/`, `.`, `..` or `control`, as device-mapper wants, and with no white space (0xa0 included) nor control character, as kcdm wants.
  * `-cipher <cipher>`: the cipher of dm-crypt, as dm-crypt takes it (`capi:cbc(aes)-plain`, `capi:cbc-aes-ce-plain`, `aes-cbc-essiv:sha256`). It goes to the kernel as it is, unchecked: a cipher the kernel builds from a template, such as `cbc(aes)`, is listed in `/proc/crypto` only once something has used it since the boot, so a check there would refuse good ciphers.
  * `-key <key>`: the key, as craf `-enc-key` takes it (see [craf.md](craf.md) for the commas): a serial number, or `[<keyring>,]<type>,<description>`, the keyring `@u` or `@s`, `@u` when not given; it is found with the same function of libkcrypto, `kc_key_spec()`, so a malformed spec, and a description that the search finds in more than one key, are a wrong usage. dm-crypt takes keys of type `logon`, `user`, `encrypted` and `trusted`, by their type and description, and looks them up for the process that loads the table: kcdm does the same search first, and refuses a key of another type, one with white space or a backslash in its description, one it does not reach by them (a key in `@u`, for example, when `@u` is not linked into the session keyring) and one where it reaches another key first, so that the key dm-crypt takes is the one `-key` names when kcdm looks. That holds when it looks: whoever can write a keyring of the search can change what dm-crypt finds a moment later, when the table is loaded. A description may hold colons: a `logon` key has one by definition (`logkey:`).
  * `-key-size <bytes>`: the length of the key, in decimal digits, 1 to 2147483647: it has no default, since neither a trusted key nor the cipher tells it (`cbc(aes)` takes 16, 24 or 32 bytes; a tagged key of the CAAM is 36), and kcdm does not check it against the cipher. dm-crypt refuses a key of another length, and the table with it. dm-crypt allocates as many bytes as the size for the key, so a size of some megabytes makes the kernel warn in its log before it refuses the table, which a kernel with `panic_on_warn` takes for a panic.
  * `-opt <parameter>`: an optional parameter of dm-crypt, such as `sector_size:512`, `allow_discards`, `same_cpu_crypt`, `submit_from_crypt_cpus`, `no_read_workqueue`, `no_write_workqueue`, `iv_large_sectors` or `integrity:<bytes>:<type>`; one `-opt` for each, in the order given, which the table counts. kcdm checks only that it is one word as the kernel reads the table, which is so for the cipher too: no white space (0xa0 included, whatever the locale), no backslash, which the kernel would take as quoting the character after it; whether the kernel takes it, the kernel decides.

kcdm then creates the device, loads the table `0 <sectors> crypt <cipher> :<bytes>:<type>:<description> 0 <major>:<minor> 0`, followed by the number of parameters and the parameters when there are any, and resumes it: the device is active. Last, it makes the node `/dev/mapper/<name>`, mode 0600, which udev would make, and takes the node or the link to it that udev made first; a block or character node, or a link, that is not the device's, as an older device leaves it, is replaced, any other file is refused. When a step fails after the device is created, kcdm removes it before it exits, so that the name is free for the next try; when that removal fails too, the message says the device stays. The device is read-write and has no UUID, as with `dmsetup create` and no `-u`.

## close

`kcdm close <name>` removes the device and its node `/dev/mapper/<name>`, if that is the node of the device (a link to it included); a file there that is not is left alone. A device in use, mounted or open, is not removed: kcdm tries for about two seconds, since a probe, such as udev's, may hold a device a moment after it was closed, then gives up. `kcdm open` tries the same when it removes a device it made.

## Exit status

  * 0 when the work is done: for open, the device is active and `/dev/mapper/<name>` is there; for close, the device is gone, and its node with it;
  * 2 for a wrong usage: an argument missing or one too many, an option given twice, a `-key-size` that is not a whole number from 1 to 2147483647, a name that kcdm refuses, a cipher or an `-opt` that is not one word as the kernel reads the table, a malformed or ambiguous `-key`;
  * 3 when kcdm could not do it, with the error of the kernel in the message: a key that is not there, of another type or that dm-crypt would not reach; a device that is not there, is not a block device, is mounted or mapped already; a name in use; a table the kernel refuses, for its cipher, the size of its key or a parameter; for close, a device in use, a name no device has, or a node that could not be removed once the device was; `/dev/mapper/control` that does not open, or ioctls that it refuses without `CAP_SYS_ADMIN`, which root has.

There is no exit status 1: kcdm judges no data. A script that opens the root treats 2 as it treats 3: an ambiguous `-key`, such as a second key with the same description in a keyring linked under `@u`, is a wrong usage for kcdm, where `dmsetup` took whichever key the kernel found first.

When the kernel refuses a table, the message has the kernel's `errno`, and the kernel's log (`dmesg`) says why: `ENOENT` ("No such file or directory") for a cipher the kernel does not have, or whose driver is not registered yet, such as a driver of a TEE probed later in the boot ("Error allocating crypto tfm" in the log), and kcdm says so; `EINVAL` for a key of another size or a parameter it does not take; an `errno` of the keyring for a key gone since kcdm looked.

## Requirements

A kernel with `BLK_DEV_DM` and `DM_CRYPT`, `KEYS`, and for a trusted or an encrypted key `TRUSTED_KEYS` or `ENCRYPTED_KEYS` (without them dm-crypt refuses such a key; Kconfig makes `DM_CRYPT` a module when one of them is a module). `/dev/mapper/control` must be there, made by devtmpfs with device-mapper in the kernel or its module loaded: an initramfs mounts devtmpfs on `/dev` itself, and kcdm says so when the node is missing. `/dev/mapper` holds it, and kcdm makes `/dev/mapper/<name>` there. The device of the mapping is `/dev/dm-<n>` too, where devtmpfs is mounted.

## Tests

The tests of kcdm (`[usage-key]`) and those of its functions in libkcrypto (`[dm]`) cover the command line, the key and the device, and never get as far as making a device, even as root. The test of a real device on two loop devices (`[loop]`) opens, writes, closes and opens again, checks the sectors with `openssl` as the oracle, and the refusals of the kernel; it makes device-mapper devices, so it runs only with `KCDM_TEST_LOOP=1`, as root, with `losetup`, `openssl` and `/dev/mapper/control`, and is `Skipped` otherwise. A run that is killed may leave the devices `kcdm-test-<pid>` and `kcdm-test-<pid>-other` and the two loop devices of its images behind, `<pid>` being that of the test.
