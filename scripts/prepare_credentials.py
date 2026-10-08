#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Materialise Sigul client credentials for the signing container.

Runs on the RUNNER, under Python 3.10 or later, before the container
starts. The container-side scripts under scripts/container/ are held
to Python 2.7 as well, for the legacy client image; nothing here is.

Responsibilities, in order:

1. Reject empty inputs, and a sigul-conf still carrying the Jenkins
   placeholders that Jenkins substitutes when it provides the file.
2. Write the passphrase file sigul reads, and the caller's client.conf.
3. Decode, decrypt (gpg_bundle.py, in a private gpg home the caller's
   cleanup removes) and unpack the PKI bundle.
4. Locate the NSS database and point every client.conf at it.

The configuration is layered as lfit/sigul-sign-action layered it:
sigul-conf becomes the image's /etc/sigul/client.conf, and a
.sigul/client.conf inside the bundle -- where sigul_setup_client keeps
nss-password -- overrides it, because the container's HOME is the
bundle's root and that is sigul's default user configuration.

Nothing here prints a credential value.
"""

from __future__ import annotations

import base64
import binascii
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path

from action_common import ActionError, info, shred_file
from gpg_bundle import UnprotectedBundleError, decrypt_bundle

# NSS ships two on-disk formats and Sigul deployments use both. These
# exact names identify the database directory whatever it is called:
# ONAP's bundle unpacks to 'sigul/', other tooling documents '.sigul/'.
# Matched exactly rather than by glob, which would also match an
# unrelated file such as 'cert-backup.db'.
NSS_DBM_FILES = frozenset({"cert8.db", "key3.db", "secmod.db"})
NSS_SQL_FILES = frozenset({"cert9.db", "key4.db", "pkcs11.txt"})
NSS_MARKERS = NSS_DBM_FILES | NSS_SQL_FILES

# The bundle unpacks into its own subdirectory. Sharing a directory
# with client.conf would let an archive carrying a top-level
# client.conf overwrite the caller's.
PKI_SUBDIR = "pki"

# sigul's default user configuration, relative to HOME.
BUNDLE_USER_CONFIG = Path(".sigul") / "client.conf"

# Where git reads a user's configuration, relative to HOME, which in
# the container is the unpacked bundle. The legacy image's git (1.8)
# predates GIT_CONFIG_GLOBAL, so a bundle carrying either file would
# configure the git that sigul's sign-git-tag runs there; such a bundle
# is refused instead, since nothing in it is git's to configure.
GIT_USER_CONFIGS = (Path(".gitconfig"), Path(".config") / "git" / "config")

# Jenkins' managed sigul-config is a template: config-file-provider
# substitutes these from the sigul-config-credentials credential when
# it provides the file. Copied from the managed-files page, the
# configuration still holds them, and sigul would then look for a
# certificate literally named '$SIGUL_CONFIG_USR'.
JENKINS_PLACEHOLDERS = ("$SIGUL_CONFIG_USR", "$SIGUL_CONFIG_PSW")

# Option names are case-insensitive to ConfigParser, as to the legacy
# action's own rewrite; section names are not, so [nss] is matched as
# sigul reads it.
_NSS_DIR_OPTION = re.compile(r"^[ \t]*nss-dir[ \t]*[:=]", re.IGNORECASE)
_SECTION_HEADER = re.compile(r"^[ \t]*\[([^\]]+)\]")


@dataclass(frozen=True)
class PreparedCredentials:
    """Where the materialised credentials live."""

    system_config: Path
    container_home: str
    container_nss_dir: str
    layered: bool


def first_line(value: str) -> str:
    """Return the first line of a passphrase.

    gpg reads only the first line of a passphrase file, and the legacy
    action sent sigul only the first line too, so a secret stored with a
    trailing newline works as it always has.
    """
    return value.split("\n", 1)[0]


def check_configuration(body: str) -> None:
    """Reject a sigul-conf that cannot work."""
    found = [token for token in JENKINS_PLACEHOLDERS if token in body]
    if found:
        raise ActionError(
            "sigul-conf still contains the Jenkins placeholder(s) "
            + ", ".join(found)
            + ". Jenkins substitutes them from its sigul-config-credentials "
            + "credential when it provides the file: replace "
            + "$SIGUL_CONFIG_USR with that credential's username and "
            + "$SIGUL_CONFIG_PSW with its password before storing sigul-conf"
        )


def decode_pki(raw: str) -> bytes:
    """Return the PKI bundle bytes, decoding base64 when present.

    The legacy action took an ASCII-armoured bundle, which passes
    through unchanged. An input is text, so binary ciphertext cannot
    arrive intact; base64 carries it instead. Anything else passes
    through for gpg to reject with its own reason.
    """
    # Armour is base64-like itself, so check for its header first:
    # decoding it as base64 would produce plausible bytes.
    if "-----BEGIN PGP" in raw:
        return raw.encode()
    try:
        decoded = base64.b64decode("".join(raw.split()), validate=True)
    except (binascii.Error, ValueError):
        return raw.encode()
    return decoded if decoded else raw.encode()


def extract_bundle(archive: Path, destination: Path) -> None:
    """Unpack the decrypted bundle safely.

    Requires tarfile's 'data' filter, which rejects absolute paths,
    parent traversal, links pointing outside the tree, device nodes and
    setuid bits. Python 3.12, 3.11.4 and 3.10.12 and later provide it.

    Deliberately no hand-rolled fallback. The obvious one -- checking
    each member's resolved path against the destination prefix -- looks
    sufficient and is not: a string prefix also matches a sibling such
    as '/dest-other', and validating members up front misses a symlink
    member whose target is written afterwards. The archive is decrypted
    key material whose contents the caller may not have inspected.
    """
    if not hasattr(tarfile, "data_filter"):
        raise ActionError(
            "this runner's Python lacks tarfile's 'data' extraction filter, "
            + "needed to unpack sigul-pki safely; use Python 3.12, 3.11.4, "
            + "3.10.12 or later"
        )
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive) as tar:
            tar.extractall(destination, filter="data")
    except tarfile.TarError as exc:
        raise ActionError(f"sigul-pki is not a readable tar archive: {exc}") from None


def find_nss_dir(root: Path) -> Path:
    """Return the directory holding the NSS database.

    A bundle holding more than one -- a backup beside the live
    database, say -- is refused, since nss-dir can name only one and
    choosing silently could point sigul at the wrong certificate. One
    directory holding both of NSS's formats is one database: that is
    how NSS upgrades a database in place, and nss-dir names the
    directory; which format the client reads is its NSS library's
    default, as it was for the legacy action and for Jenkins. It is
    noted, since it explains a certificate that is not the one expected.
    """
    found = sorted(
        {
            path.parent
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink() and path.name in NSS_MARKERS
        }
    )
    if len(found) == 1:
        names = {p.name for p in found[0].iterdir() if p.is_file()}
        if names & NSS_DBM_FILES and names & NSS_SQL_FILES:
            info(
                "the NSS database holds both formats, dbm (cert8.db) and sql "
                + "(cert9.db); the client image's NSS decides which it reads"
            )
        return found[0]
    # List structure, never contents: the bundle holds key material.
    if found:
        detail = "\n".join(f"  {p.relative_to(root)}/" for p in found)
        raise ActionError(
            f"The sigul-pki bundle holds {len(found)} NSS databases, and nss-dir "
            + "can name only one. Pack the bundle with the one the client "
            + "certificate lives in:\n"
            + detail
        )
    directories = sorted(
        f"  {p.relative_to(root)}/" for p in root.rglob("*") if p.is_dir()
    )
    detail = "\n".join(directories) if directories else "  (no directories)"
    raise ActionError(
        "No NSS database found in the sigul-pki bundle. Expected one of "
        + ", ".join(sorted(NSS_MARKERS))
        + ".\nThe bundle unpacked to:\n"
        + detail
    )


def rewrite_nss_dir(text: str, container_nss: str, add_if_missing: bool) -> str:
    """Point a client configuration at the unpacked database.

    A client.conf carries an absolute nss-dir naming wherever the
    database sat on its originating machine -- ONAP's says
    /home/jenkins/sigul -- which does not exist in the container.
    Rewriting it lets a configuration travel verbatim from Jenkins.

    Only the [nss] section's nss-dir is Sigul's, so only that one
    changes: the first is replaced and any duplicates dropped, so the
    section cannot end up ambiguous, while any other section is left as
    written. Where [nss] sets none, one is added when asked.
    """
    entry = f"nss-dir: {container_nss}"
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    section = ""
    nss_header = -1
    replaced = False
    for line in lines:
        header = _SECTION_HEADER.match(line)
        if header:
            section = header.group(1).strip()
            if section == "nss" and nss_header < 0:
                nss_header = len(out)
        elif section == "nss" and _NSS_DIR_OPTION.match(line):
            if not replaced:
                out.append(entry + ("\n" if line.endswith("\n") else ""))
                replaced = True
            continue
        out.append(line)
    if replaced or not add_if_missing:
        return "".join(out)
    if nss_header >= 0:
        if not out[nss_header].endswith("\n"):
            out[nss_header] += "\n"
        out.insert(nss_header + 1, entry + "\n")
        return "".join(out)
    return text.rstrip("\n") + f"\n\n[nss]\n{entry}\n"


def require(name: str, value: str) -> str:
    """Return value, failing when it is blank."""
    if not value.strip():
        raise ActionError(f"Input '{name}' is required")
    return value


def write_private(path: Path, data: bytes) -> None:
    """Write a file readable by its owner only."""
    path.touch(mode=0o600, exist_ok=False)
    _ = path.write_bytes(data)


def prepare(
    creds: Path,
    gnupg_home: Path,
    container_creds: str,
    config_body: str,
    password: str,
    pki_raw: str,
) -> PreparedCredentials:
    """Materialise the credentials under creds, for mounting at
    container_creds. gnupg_home must lie outside creds."""
    config_body = require("sigul-conf", config_body)
    password = require("sigul-pass", password)
    pki_raw = require("sigul-pki", pki_raw)
    check_configuration(config_body)

    passphrase = first_line(password)
    if not passphrase:
        raise ActionError("the first line of sigul-pass is empty")

    creds.mkdir(mode=0o700, parents=True, exist_ok=True)
    gnupg_home.mkdir(mode=0o700, parents=True, exist_ok=True)

    # sigul reads the key passphrase from stdin up to a NUL. These are
    # the bytes the legacy action and global-jjb send.
    write_private(creds / "password", passphrase.encode() + b"\0\n")

    gpg_passphrase = gnupg_home / "passphrase"
    write_private(gpg_passphrase, passphrase.encode() + b"\n")
    encrypted = gnupg_home / "pki.gpg"
    write_private(encrypted, decode_pki(pki_raw))
    decrypted = gnupg_home / "pki.tar"
    try:
        decrypt_bundle(encrypted, gpg_passphrase, decrypted, gnupg_home)
    except ActionError as exc:
        # gpg can have written the plaintext before deciding to fail, as
        # it does for a message without integrity protection.
        shred_file(decrypted)
        if isinstance(exc, UnprotectedBundleError):
            raise
        rest = password.split("\n", 1)[1] if "\n" in password else ""
        if rest.strip():
            raise ActionError(
                "Could not decrypt sigul-pki. sigul-pass has more than one "
                + "line and only its first line is used; re-encrypt sigul-pki "
                + "with the first line of sigul-pass"
            ) from None
        raise ActionError(
            "Could not decrypt sigul-pki. It must be a tar.xz archive, "
            + f"GPG-encrypted with sigul-pass. gpg said: {exc}"
        ) from None
    finally:
        shred_file(gpg_passphrase)
        shred_file(encrypted)

    pki_root = creds / PKI_SUBDIR
    try:
        extract_bundle(decrypted, pki_root)
    finally:
        shred_file(decrypted)

    nss_dir = find_nss_dir(pki_root)
    for relative in GIT_USER_CONFIGS:
        if (pki_root / relative).exists() or (pki_root / relative).is_symlink():
            raise ActionError(
                f"the bundle carries {relative}, which git would read as the "
                + "user's configuration inside the client container, where it "
                + "could name commands to run; remove it from the bundle"
            )
    container_nss = f"{container_creds}/{nss_dir.relative_to(creds).as_posix()}"
    info(f"NSS database found at {nss_dir.relative_to(creds).as_posix()}")

    system_config = creds / "client.conf"
    write_private(
        system_config,
        rewrite_nss_dir(config_body, container_nss, add_if_missing=True).encode(),
    )

    user_config = pki_root / BUNDLE_USER_CONFIG
    if user_config.is_symlink():
        # The extraction filter admits a link that stays inside the
        # bundle, and sigul would follow it to a configuration whose
        # nss-dir has not been rewritten, overriding the one that has.
        raise ActionError(
            "the bundle's .sigul/client.conf is a symlink, which sigul would "
            + "follow to a configuration the action cannot adjust; pack the "
            + "bundle with the file itself"
        )
    layered = user_config.is_file()
    if layered:
        _ = user_config.write_text(
            rewrite_nss_dir(
                user_config.read_text(), container_nss, add_if_missing=False
            )
        )
        info(
            "the bundle's .sigul/client.conf overrides sigul-conf where both "
            + "set a value, as with lfit/sigul-sign-action"
        )

    return PreparedCredentials(
        system_config=system_config,
        container_home=f"{container_creds}/{PKI_SUBDIR}",
        container_nss_dir=container_nss,
        layered=layered,
    )
