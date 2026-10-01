#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Materialise Sigul client credentials for the signing container.

Runs on the RUNNER, before the container starts, where Python 3 is
available. The container entrypoints stay in shell because the legacy
Sigul image is CentOS 7 and ships Python 2.7 only.

Responsibilities, in order:

1. Reject empty credential inputs. A composite action does not enforce
   ``required: true``, so an omitted input arrives as an empty string
   and would otherwise become an empty config file, surfacing much
   later as a confusing Sigul error.
2. Write ``client.conf`` and the passphrase file.
3. Decode, decrypt and unpack the PKI bundle.
4. Locate the NSS database and rewrite ``nss-dir`` to the path the
   container will see.

Nothing here prints a credential value.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import NoReturn

# NSS ships two on-disk formats and Sigul deployments use both. These
# exact names identify the database directory whatever it is called --
# ONAP's bundle unpacks to 'sigul/', other tooling documents '.sigul/'.
#
# Matched exactly rather than by glob: a 'cert*.db' pattern also
# matches an unrelated file such as 'cert-backup.db', which would
# point nss-dir at the wrong directory instead of failing cleanly.
NSS_MARKERS = frozenset(
    {"cert8.db", "cert9.db", "key3.db", "key4.db", "secmod.db", "pkcs11.txt"}
)

# The bundle unpacks into its own subdirectory. Sharing a directory
# with client.conf would let an archive carrying a top-level
# client.conf overwrite the caller's, restoring stale bridge settings.
PKI_SUBDIR = "pki"


def fail(message: str) -> NoReturn:
    """Emit a GitHub Actions error annotation and exit non-zero.

    Annotated NoReturn rather than None so static analysis knows the
    caller's flow stops here; otherwise every value assigned inside a
    guarded try block reads as possibly unbound afterwards.
    """
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def require_env(name: str) -> str:
    """Return an environment variable, failing if absent or empty."""
    value = os.environ.get(name, "")
    if not value.strip():
        fail(f"{name} is required but arrived empty")
    return value


def decode_pki(raw: str) -> bytes:
    """Return the PKI bundle bytes, decoding base64 when present.

    A binary ``tar.xz`` does not survive every secret store intact, so
    base64 is tolerated. ONAP's bundle is ASCII-armoured PGP and passes
    through unchanged.
    """
    stripped = "".join(raw.split())
    # Armoured PGP is itself base64-ish, so check for the armour header
    # first: decoding it as base64 would produce plausible bytes.
    if "-----BEGIN PGP" in raw:
        return raw.encode()
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return raw.encode()
    return decoded if decoded else raw.encode()


def decrypt_bundle(encrypted: Path, passphrase: Path, output: Path) -> None:
    """GPG-decrypt the PKI bundle.

    GnuPG 2.1 and later refuse ``--passphrase-file`` in batch mode
    unless ``--pinentry-mode loopback`` is given: without it gpg
    delegates to pinentry, which has no terminal in a workflow step and
    fails even when the passphrase is correct. GnuPG 1.x does not know
    the option, so fall back rather than assume a version.
    """
    base = [
        "gpg",
        "--batch",
        "--quiet",
        "--yes",
        "--passphrase-file",
        str(passphrase),
        "--output",
        str(output),
        "--decrypt",
        str(encrypted),
    ]
    attempts = (["gpg", "--pinentry-mode", "loopback"] + base[1:], base)

    last = ""
    for argv in attempts:
        try:
            done = subprocess.run(argv, capture_output=True, text=True)
        except FileNotFoundError:
            fail(
                "gpg not found on the runner. This action needs gpg, tar "
                + "with xz support and base64 available on the host."
            )
        if done.returncode == 0:
            return
        stderr_lines = (done.stderr or "").strip().splitlines()
        last = stderr_lines[-1] if stderr_lines else ""
        # An unknown option means an older gpg; try the plain form.
        if "pinentry-mode" not in last:
            break

    fail(
        "Failed to decrypt sigul-pki. It must be a tar.xz archive, "
        + f"GPG-encrypted with the value of sigul-password. gpg said: {last}"
    )


def extract_bundle(archive: Path, destination: Path) -> None:
    """Unpack the decrypted bundle safely.

    Requires tarfile's ``data`` filter, which rejects absolute paths,
    parent traversal, links pointing outside the tree, device nodes
    and setuid bits. Python 3.12 and later provide it, as every
    supported runner image does.

    Deliberately no hand-rolled fallback. The obvious one -- checking
    each member's resolved path against the destination prefix --
    looks sufficient and is not: a string prefix also matches a
    sibling such as ``/dest-other``, and validating members up front
    misses a symlink member whose target is written to afterwards.
    An insecure fallback is worse than refusing to run, because the
    archive here is decrypted key material whose contents the caller
    may not have inspected.
    """
    if not hasattr(tarfile, "data_filter"):
        fail(
            "Python 3.12 or later is required to unpack sigul-pki safely "
            + "(tarfile's 'data' extraction filter is unavailable here)"
        )

    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive) as tar:
            tar.extractall(destination, filter="data")
    except tarfile.TarError as exc:
        fail(f"sigul-pki is not a readable tar archive: {exc}")


def find_nss_dir(root: Path) -> Path:
    """Return the directory holding the NSS database."""
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name in NSS_MARKERS:
            return path.parent

    # List structure, never contents: the bundle holds key material.
    found = sorted(f"  {p.relative_to(root)}/" for p in root.rglob("*") if p.is_dir())
    detail = "\n".join(found) if found else "  (no directories)"
    fail(
        "No NSS database found in the sigul-pki bundle. Expected one of "
        + ", ".join(sorted(NSS_MARKERS))
        + ".\nThe bundle unpacked to:\n"
        + detail
    )


def rewrite_nss_dir(config: Path, container_nss: str) -> None:
    """Point the client configuration at the unpacked database.

    A ``client.conf`` carries an absolute ``nss-dir`` naming wherever
    the database sat on its originating machine -- ONAP's says
    ``/home/jenkins/sigul`` -- which does not exist in the container.
    Rewriting it means a configuration travels verbatim from Jenkins.
    """
    text = config.read_text()
    entry = f"nss-dir: {container_nss}"

    # Accept 'nss-dir:' and 'nss-dir =', with or without indentation;
    # both spellings appear in the wild.
    pattern = re.compile(r"^[ \t]*nss-dir[ \t]*[:=].*$", re.MULTILINE)
    matches = list(pattern.finditer(text))

    if matches:
        # Replace the first entry and drop any others, so the file
        # cannot end up ambiguous. Rebuilt by slicing rather than with
        # a second sub(): the replacement itself matches the pattern,
        # so a follow-up sub() would delete the line just written.
        pieces: list[str] = []
        cursor = 0
        for index, match in enumerate(matches):
            pieces.append(text[cursor : match.start()])
            if index == 0:
                pieces.append(entry)
                cursor = match.end()
            else:
                # Swallow the trailing newline too, so removing a
                # duplicate leaves no blank line behind.
                cursor = match.end()
                if text[cursor : cursor + 1] == "\n":
                    cursor += 1
        pieces.append(text[cursor:])
        text = "".join(pieces)
    elif re.search(r"^[ \t]*\[nss\]", text, re.MULTILINE):
        text = re.sub(
            r"^([ \t]*\[nss\].*)$",
            r"\1\n" + entry,
            text,
            count=1,
            flags=re.MULTILINE,
        )
    else:
        # No [nss] section: append one so a minimal config still works.
        text = text.rstrip("\n") + f"\n\n[nss]\n{entry}\n"

    _ = config.write_text(text)


def main() -> int:
    creds = Path(require_env("CREDS_DIR"))
    container_creds = require_env("CONTAINER_CREDS")

    config_body = require_env("SIGUL_CONFIG_BODY")
    password = require_env("SIGUL_PASSWORD_VALUE")
    pki_raw = require_env("SIGUL_PKI_VALUE")
    _ = require_env("SIGUL_KEY")

    _ = os.umask(0o077)
    creds.mkdir(parents=True, exist_ok=True)
    creds.chmod(0o700)

    config_path = creds / "client.conf"
    _ = config_path.write_text(config_body)

    # Sigul reads the passphrase from stdin and expects it
    # NUL-terminated, which global-jjb achieves with 's/$/\x0/' over a
    # file ending in a newline. Reproduce those bytes exactly: this is
    # the sequence the deployed 0.207 server is known to accept.
    _ = (creds / "password").write_bytes(password.encode() + b"\0\n")

    # gpg needs the passphrase without the NUL.
    gpg_pass = creds / "gpgpass"
    _ = gpg_pass.write_text(password)

    encrypted = creds / "pki.enc"
    _ = encrypted.write_bytes(decode_pki(pki_raw))

    decrypted = creds / "pki.tar"
    decrypt_bundle(encrypted, gpg_pass, decrypted)
    gpg_pass.unlink()
    encrypted.unlink()

    pki_root = creds / PKI_SUBDIR
    extract_bundle(decrypted, pki_root)
    decrypted.unlink()

    nss_dir = find_nss_dir(pki_root)
    relative = nss_dir.relative_to(creds).as_posix()
    container_nss = f"{container_creds}/{relative}"

    print(f"INFO: NSS database found at {relative}")
    print(f"INFO: rewriting nss-dir to {container_nss}")
    rewrite_nss_dir(config_path, container_nss)
    print("INFO: client configuration prepared")

    if shutil.which("docker") is None:
        fail("docker not found on the runner; this action signs in a container")

    return 0


if __name__ == "__main__":
    sys.exit(main())
