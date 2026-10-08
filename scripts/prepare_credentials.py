#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Materialise Sigul client credentials for the signing container.

Runs on the RUNNER, under Python 3.10 or later. GPG decryption, bounded
archive extraction and parser-safe configuration rewriting are separate
credential helpers. The caller owns cleanup of both private directories.

The configuration is layered as lfit/sigul-sign-action layered it:
sigul-conf becomes the image's /etc/sigul/client.conf, and a
.sigul/client.conf inside the bundle -- where sigul_setup_client keeps
nss-password -- overrides it. Nothing here prints a credential value.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from pathlib import Path

from action_common import ActionError, info, shred_file
from credential_archive import extract_bundle as extract_bundle
from credential_config import MAX_CONFIG_BYTES, parse_configuration
from credential_config import rewrite_nss_dir as rewrite_nss_dir
from credential_files import write_private as write_private
from gpg_bundle import UnprotectedBundleError, decrypt_bundle

# These exact names distinguish NSS databases from unrelated backup files.
NSS_DBM_FILES = frozenset({"cert8.db", "key3.db", "secmod.db"})
NSS_SQL_FILES = frozenset({"cert9.db", "key4.db", "pkcs11.txt"})
NSS_MARKERS = NSS_DBM_FILES | NSS_SQL_FILES

# Keep the archive separate from the caller's system configuration.
PKI_SUBDIR = "pki"
BUNDLE_USER_CONFIG = Path(".sigul") / "client.conf"

# The legacy client's git predates GIT_CONFIG_GLOBAL. The bundle is HOME,
# but has no business configuring git or commands git could execute.
GIT_USER_CONFIGS = (Path(".gitconfig"), Path(".config") / "git" / "config")
JENKINS_PLACEHOLDERS = ("$SIGUL_CONFIG_USR", "$SIGUL_CONFIG_PSW")
MAX_PKI_BYTES = 1024 * 1024
MAX_PKI_TEXT_CHARACTERS = 2 * MAX_PKI_BYTES


@dataclass(frozen=True)
class PreparedCredentials:
    """Where the materialised credentials live."""

    system_config: Path
    container_home: str
    container_nss_dir: str
    layered: bool


def first_line(value: str) -> str:
    """Use the first passphrase line, as both GPG and the legacy action do."""
    return value.split("\n", 1)[0]


def check_configuration(body: str) -> None:
    """Reject Jenkins templates and malformed INI without quoting values."""
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
    _ = parse_configuration(body)


def decode_pki(raw: str) -> bytes:
    """Decode optional base64 with bounded input and ciphertext sizes."""
    if len(raw) > MAX_PKI_TEXT_CHARACTERS:
        raise ActionError("sigul-pki input exceeds 2 MiB of text")
    if "-----BEGIN PGP" in raw:
        data = raw.encode()
    else:
        try:
            data = base64.b64decode("".join(raw.split()), validate=True) or raw.encode()
        except (binascii.Error, ValueError):
            data = raw.encode()
    if len(data) > MAX_PKI_BYTES:
        raise ActionError("sigul-pki ciphertext exceeds 1 MiB")
    return data


def find_nss_dir(root: Path) -> Path:
    """Find one NSS database; refuse ambiguous live/backup combinations."""
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
    # Only validated, bounded archive paths are listed; never file contents.
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


def require(name: str, value: str) -> str:
    """Return value, failing when it is blank."""
    if not value.strip():
        raise ActionError(f"Input '{name}' is required")
    return value


def private_directory(path: Path) -> None:
    """Use only an empty mode-0700 directory, never an existing credential tree."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_mode & 0o777 != 0o700 or any(path.iterdir()):
        raise ActionError("Credential directories must be empty, private directories")


def rewrite_user_config(path: Path, container_nss: str) -> None:
    """Replace a bounded user configuration using an exclusive private write."""
    with path.open("rb") as stream:
        data = stream.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise ActionError("Sigul configuration exceeds 1 MiB")
    rewritten = rewrite_nss_dir(
        data.decode("utf-8"), container_nss, add_if_missing=False
    )
    shred_file(path)
    write_private(path, rewritten.encode("utf-8"))


def prepare(
    creds: Path,
    gnupg_home: Path,
    container_creds: str,
    config_body: str,
    password: str,
    pki_raw: str,
) -> PreparedCredentials:
    """Prepare credentials without exposing values through filesystem/codec errors."""
    try:
        return _prepare(
            creds, gnupg_home, container_creds, config_body, password, pki_raw
        )
    except (OSError, UnicodeError):
        raise ActionError(
            "Could not read or write the private Sigul credential files"
        ) from None


def _prepare(
    creds: Path,
    gnupg_home: Path,
    container_creds: str,
    config_body: str,
    password: str,
    pki_raw: str,
) -> PreparedCredentials:
    """Materialise the credentials; the caller erases both directories on exit."""
    config_body = require("sigul-conf", config_body)
    password = require("sigul-pass", password)
    pki_raw = require("sigul-pki", pki_raw)
    check_configuration(config_body)
    ciphertext = decode_pki(pki_raw)
    passphrase = first_line(password)
    if not passphrase:
        raise ActionError("the first line of sigul-pass is empty")
    if creds.resolve().is_relative_to(
        gnupg_home.resolve()
    ) or gnupg_home.resolve().is_relative_to(creds.resolve()):
        raise ActionError("The credential directory and GPG home must not overlap")
    private_directory(creds)
    private_directory(gnupg_home)
    write_private(creds / "password", passphrase.encode() + b"\0\n")

    gpg_passphrase = gnupg_home / "passphrase"
    encrypted = gnupg_home / "pki.gpg"
    decrypted = gnupg_home / "pki.tar"
    try:
        write_private(gpg_passphrase, passphrase.encode() + b"\n")
        write_private(encrypted, ciphertext)
        decrypt_bundle(encrypted, gpg_passphrase, decrypted, gnupg_home)
    except ActionError as exc:
        # GPG can write plaintext before deciding its authentication failed.
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
        raise
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
    layered = user_config.is_file()
    if layered:
        rewrite_user_config(user_config, container_nss)
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
