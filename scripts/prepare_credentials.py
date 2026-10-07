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
3. Decode, decrypt and unpack the PKI bundle, with gpg confined to a
   private home that the caller's cleanup removes.
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
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

from action_common import ActionError, info, minimal_env, shred_file, system_tool

# NSS ships two on-disk formats and Sigul deployments use both. These
# exact names identify the database directory whatever it is called:
# ONAP's bundle unpacks to 'sigul/', other tooling documents '.sigul/'.
# Matched exactly rather than by glob, which would also match an
# unrelated file such as 'cert-backup.db'.
NSS_MARKERS = frozenset(
    {"cert8.db", "cert9.db", "key3.db", "key4.db", "secmod.db", "pkcs11.txt"}
)

# The bundle unpacks into its own subdirectory. Sharing a directory
# with client.conf would let an archive carrying a top-level
# client.conf overwrite the caller's.
PKI_SUBDIR = "pki"

# sigul's default user configuration, relative to HOME.
BUNDLE_USER_CONFIG = Path(".sigul") / "client.conf"

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


class UnprotectedBundleError(ActionError):
    """sigul-pki was encrypted without integrity protection."""


# What gpg says, since 2.2.8, of a message without an MDC: the
# modification detection code that GnuPG 2.0 and earlier omitted by
# default with their default cipher, CAST5. Earlier gpg decrypted such
# a message with a warning; the legacy action's CentOS 7 container had
# GnuPG 2.0.22, so a bundle it accepted can be refused here.
_NO_INTEGRITY = ("message was not integrity protected", "decryption forced to fail")


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


def decrypt_bundle(encrypted: Path, passphrase: Path, output: Path, home: Path) -> None:
    """GPG-decrypt the PKI bundle inside a private gpg home.

    The private home keeps the runner user's keyring and agent out of
    it. --no-symkey-cache stops gpg-agent caching the passphrase, and
    the caller kills that agent and removes the home afterwards.
    GnuPG 2.1 and later need --pinentry-mode loopback to take the
    passphrase from a file in batch mode; older releases reject one or
    both options, so each is dropped only when gpg names it as invalid.

    A message without integrity protection is refused, as gpg refuses
    it: --ignore-mdc-error would decrypt it, and would also decrypt
    one an attacker had altered, for everyone, to spare the one caller
    who should re-encrypt. That caller is told so instead.
    """
    optional: list[str] = ["--pinentry-mode", "loopback", "--no-symkey-cache"]
    rest = [
        "--batch",
        "--quiet",
        "--yes",
        "--no-tty",
        "--passphrase-file",
        str(passphrase),
        "--output",
        str(output),
        "--decrypt",
        str(encrypted),
    ]
    env = minimal_env({"HOME": str(home)})
    while True:
        argv = ["gpg", "--homedir", str(home), *optional, *rest]
        try:
            done = subprocess.run(
                argv, capture_output=True, text=True, env=env, check=False
            )
        except FileNotFoundError:
            raise ActionError("gpg is not installed on the runner") from None
        if done.returncode == 0:
            return
        stderr = done.stderr or ""
        if "invalid option" in stderr and "--no-symkey-cache" in optional:
            if "no-symkey-cache" in stderr:
                optional.remove("--no-symkey-cache")
                continue
        if "invalid option" in stderr and "--pinentry-mode" in optional:
            if "pinentry-mode" in stderr:
                optional = [
                    o for o in optional if o not in ("--pinentry-mode", "loopback")
                ]
                continue
        lines = [line for line in stderr.splitlines() if line.strip()]
        if any(marker in stderr for marker in _NO_INTEGRITY):
            raise UnprotectedBundleError(
                "sigul-pki was encrypted without integrity protection (an MDC), "
                + "as GnuPG 2.0 and earlier did by default, and this runner's gpg "
                + "refuses to decrypt such a message. The passphrase may well be "
                + "right. Re-encrypt the bundle with a current GnuPG, which adds "
                + "the protection, and store the result as sigul-pki: "
                + "gpg --symmetric --cipher-algo AES256 --armor sigul.tar.xz"
            )
        raise ActionError(lines[-1] if lines else "gpg failed")


def kill_gpg_agent(home: Path) -> None:
    """Stop any gpg-agent started for the private home.

    gpgconf ships with every gpg that starts an agent, so where it is
    absent there is no agent to stop.
    """
    gpgconf = system_tool("gpgconf")
    if gpgconf is None or not home.exists():
        return
    _ = subprocess.run(
        [gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
        capture_output=True,
        env=minimal_env({"HOME": str(home)}),
        check=False,
    )


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
    """Return the directory holding the NSS database."""
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and path.name in NSS_MARKERS:
            return path.parent
    # List structure, never contents: the bundle holds key material.
    found = sorted(f"  {p.relative_to(root)}/" for p in root.rglob("*") if p.is_dir())
    detail = "\n".join(found) if found else "  (no directories)"
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
    container_nss = f"{container_creds}/{nss_dir.relative_to(creds).as_posix()}"
    info(f"NSS database found at {nss_dir.relative_to(creds).as_posix()}")

    system_config = creds / "client.conf"
    write_private(
        system_config,
        rewrite_nss_dir(config_body, container_nss, add_if_missing=True).encode(),
    )

    user_config = pki_root / BUNDLE_USER_CONFIG
    layered = user_config.is_file() and not user_config.is_symlink()
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
