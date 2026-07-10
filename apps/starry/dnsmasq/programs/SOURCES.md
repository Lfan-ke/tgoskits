# dnsmasq provenance

No binaries are committed. `prebuild.sh` stages dnsmasq and a TFTP client from the Alpine
packages recorded in `../apk.lock`: branch, repository, version and the sha256 of each file,
per architecture. A package is fetched from a mirror and used only if its sha256 matches the
lock, so a given commit always tests the same bytes.

## Packages (Alpine `main`)

| package | binary staged | role |
|:--:|:--:|:--:|
| `dnsmasq` | `/usr/sbin/dnsmasq` | DNS forwarder + authoritative records + DHCP/TFTP server |
| `tftp-hpa` | `/usr/bin/tftp` | TFTP client that drives the integrated TFTP server end to end |

Both need only `libc.musl`, already in the Alpine base rootfs, so no shared library is
staged. The DNS clients (`busybox nslookup`, which accepts `-type=` for
a/aaaa/cname/mx/txt/ptr/srv) and the DHCP client (`busybox udhcpc`) are base busybox applets.
The binaries stay musl-dynamic on all four architectures.

## Updating the lock

`../update-apk-lock.sh [BRANCH]` reads the live APKINDEX, downloads the version it lists for
every package and architecture, and records the sha256 only after `../apk_verify.py` has
checked the file: an RSA signature over the control stream by one of the Alpine release keys
committed in `../keys/`, and the data stream against the `datahash` in the signed
`.PKGINFO`. The verifier also rejects a tampered and a truncated copy of each file before it
reports success, so a verifier that stopped checking cannot pass.

`prebuild.sh` stops with a message naming `update-apk-lock.sh` when the rootfs is a different
Alpine branch from the lock, or when no mirror still serves a locked file with its sha256
(Alpine drops superseded versions from stable branches). The new versions then arrive as a
change to `apk.lock`.

## Mirrors

Packages are fetched from `https://dl-cdn.alpinelinux.org/alpine` first, then
`https://mirrors.tuna.tsinghua.edu.cn/alpine`; `DNSMASQ_APK_MIRROR` replaces the first. Since
every file is checked against the lock, the mirror does not need to be trusted.
