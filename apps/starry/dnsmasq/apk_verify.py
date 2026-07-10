#!/usr/bin/env python3
"""apk_verify.py KEYS_DIR APK - check an Alpine APK against Alpine's own signature.

An APK v2 file is three concatenated gzip streams: signature, control and data. The
signature stream holds `.SIGN.RSA.<key>`, an RSA signature over sha1 of the control stream
made with an Alpine release key, and the control stream's .PKGINFO records `datahash`, the
sha256 of the data stream. A valid signature from a committed key plus a matching data hash
therefore covers the whole file. The streams are cut where zlib stops decoding, because a
gzip reader reads ahead into the next stream.

Before reporting success the check is run again on a copy with one control byte flipped and
on a copy cut in half; if either is accepted the verifier itself is broken and this fails.
"""

import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import zlib


def split_streams(raw):
    first = zlib.decompressobj(wbits=31)
    first.decompress(raw)
    first.flush()
    rest = first.unused_data
    signature = raw[: len(raw) - len(rest)]
    second = zlib.decompressobj(wbits=31)
    control = second.decompress(rest) + second.flush()
    if not second.eof:
        raise ValueError("control stream is incomplete")
    data = second.unused_data
    return signature, rest[: len(rest) - len(data)], control, data


def read_member(tar, member):
    stream = tar.extractfile(member)
    if stream is None:
        raise KeyError(f"{member} is not a regular file")
    return stream.read()


def check(raw, keys_dir):
    """Returns (signer, None) for a good APK and (None, reason) otherwise."""
    try:
        signature_stream, control_stream, control, data = split_streams(raw)
    except (zlib.error, ValueError) as err:
        return None, f"malformed APK ({err})"
    try:
        with tarfile.open(fileobj=io.BytesIO(signature_stream)) as tar:
            member = next(m for m in tar.getmembers() if m.name.startswith(".SIGN.RSA."))
            signer = member.name[len(".SIGN.RSA."):]
            signature = read_member(tar, member)
    except (tarfile.TarError, KeyError, StopIteration) as err:
        return None, f"no readable signature ({err!r})"
    key = os.path.join(keys_dir, signer)
    if not os.path.isfile(key):
        return None, f"signer {signer!r} is not a committed Alpine key"
    with tempfile.NamedTemporaryFile() as sig, tempfile.NamedTemporaryFile() as ctl:
        sig.write(signature)
        sig.flush()
        ctl.write(control_stream)
        ctl.flush()
        result = subprocess.run(
            ["openssl", "dgst", "-sha1", "-verify", key, "-signature", sig.name, ctl.name],
            capture_output=True,
            text=True,
        )
    if result.returncode != 0 or "Verified OK" not in result.stdout:
        return None, f"signature by {signer} does not verify"
    try:
        with tarfile.open(fileobj=io.BytesIO(control)) as tar:
            pkginfo = read_member(tar, ".PKGINFO").decode()
        datahash = next(
            line.split("=", 1)[1].strip()
            for line in pkginfo.splitlines()
            if line.startswith("datahash")
        )
    except (tarfile.TarError, KeyError, StopIteration) as err:
        return None, f"no datahash in the signed .PKGINFO ({err!r})"
    if hashlib.sha256(data).hexdigest() != datahash:
        return None, "data stream does not match the signed datahash"
    return signer, None


def main():
    keys_dir, path = sys.argv[1], sys.argv[2]
    raw = open(path, "rb").read()
    signer, reason = check(raw, keys_dir)
    if reason:
        sys.exit(f"apk_verify: {path}: {reason}")

    tampered = bytearray(raw)
    first = zlib.decompressobj(wbits=31)
    first.decompress(raw)
    tampered[len(raw) - len(first.unused_data) + 8] ^= 0xFF
    for name, copy in (("tampered", bytes(tampered)), ("truncated", raw[: len(raw) // 2])):
        if check(copy, keys_dir)[1] is None:
            sys.exit(f"apk_verify: {path}: a {name} copy was accepted, so the check is broken")

    print(f"apk_verify: {os.path.basename(path)} signed by {signer}", file=sys.stderr)


if __name__ == "__main__":
    main()
