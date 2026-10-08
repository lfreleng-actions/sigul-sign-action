#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Authenticated, bounded GPG decryption in a caller-owned private home."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from action_common import ActionError, minimal_env, system_tool, warning
from credential_archive import MAX_ARCHIVE_BYTES
from credential_files import write_private
from process_control import capture_text


class UnprotectedBundleError(ActionError):
    """sigul-pki was encrypted without integrity protection."""


_NO_INTEGRITY = ("message was not integrity protected", "decryption forced to fail")
GPG_TIMEOUT_SECONDS = 60
GPGCONF_TIMEOUT_SECONDS = 2
_UNPROTECTED_MESSAGE = (
    "sigul-pki was encrypted without integrity protection (an MDC or AEAD). "
    "Re-encrypt the bundle with a current GnuPG and store the result as "
    "sigul-pki: gpg --symmetric --cipher-algo AES256 --armor sigul.tar.xz"
)
_DECRYPTION_ERROR = (
    "Could not decrypt sigul-pki as one authenticated GPG-encrypted archive. "
    "Check sigul-pass and re-encrypt the bundle with a current GnuPG"
)


def authenticated_status(status: str) -> bool:
    """Require one authenticated plaintext, not just a successful GPG exit.

    DECRYPTION_INFO is emitted even on failure. DECRYPTION_OKAY plus a zero
    exit status establishes success; DECRYPTION_INFO must additionally name
    an MDC or AEAD method, since old GPG also accepted unprotected messages.
    GOODMDC is deprecated by GPG and is not required for AEAD decryption.
    """
    records = [
        line[len("[GNUPG:] ") :].split()
        for line in status.splitlines()
        if line.startswith("[GNUPG:] ")
    ]
    records = [record for record in records if record]
    info = [record[1:] for record in records if record[0] == "DECRYPTION_INFO"]
    if len(info) != 1 or not 2 <= len(info[0]) <= 4:
        return False
    try:
        fields = [int(field) for field in info[0]]
    except ValueError:
        return False
    mdc = fields[0]
    aead = fields[2] if len(fields) >= 3 else 0
    if mdc == 0 and aead == 0:
        raise UnprotectedBundleError(_UNPROTECTED_MESSAGE)
    if min(fields) < 0 or (len(fields) == 4 and fields[3] != 0):
        return False
    codes = [record[0] for record in records]
    if any(
        code in codes
        for code in (
            "BADMDC",
            "ERRMDC",
            "DECRYPTION_FAILED",
            "FAILURE",
            "ERROR",
            "NODATA",
            "UNEXPECTED",
        )
    ):
        return False
    return all(
        codes.count(code) == 1
        for code in (
            "BEGIN_DECRYPTION",
            "DECRYPTION_OKAY",
            "END_DECRYPTION",
            "PLAINTEXT",
        )
    )


def decrypt_bundle(encrypted: Path, passphrase: Path, output: Path, home: Path) -> None:
    """Decrypt with a total 60-second deadline, 64-MiB output cap and safe errors."""
    optional = ["--pinentry-mode", "loopback", "--no-symkey-cache"]
    rest = [
        "--batch",
        "--quiet",
        "--yes",
        "--no-tty",
        "--status-fd",
        "1",
        "--max-output",
        str(MAX_ARCHIVE_BYTES),
        "--passphrase-file",
        str(passphrase),
        "--output",
        str(output),
        "--decrypt",
        str(encrypted),
    ]
    env = minimal_env({"HOME": str(home)})
    deadline = time.monotonic() + GPG_TIMEOUT_SECONDS
    try:
        # --yes permits GPG to replace this file during compatibility retries.
        # It belongs to this call, and has never been a link or another file.
        write_private(output, b"")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ActionError("Could not decrypt sigul-pki within 60 seconds")
            done = capture_text(
                ["gpg", "--homedir", str(home), *optional, *rest],
                env=env,
                timeout=remaining,
            )
            stderr = done.stderr or ""
            if done.returncode != 0 and "invalid option" in stderr:
                if "--no-symkey-cache" in optional and "no-symkey-cache" in stderr:
                    optional.remove("--no-symkey-cache")
                    continue
                if "--pinentry-mode" in optional and "pinentry-mode" in stderr:
                    optional = [
                        option
                        for option in optional
                        if option not in ("--pinentry-mode", "loopback")
                    ]
                    continue
            if any(marker in stderr for marker in _NO_INTEGRITY):
                raise UnprotectedBundleError(_UNPROTECTED_MESSAGE)
            authenticated = authenticated_status(done.stdout or "")
            if done.returncode != 0 or not authenticated:
                raise ActionError(_DECRYPTION_ERROR)
            if output.stat().st_size > MAX_ARCHIVE_BYTES:
                raise ActionError("Could not decrypt sigul-pki: archive exceeds 64 MiB")
            return
    except subprocess.TimeoutExpired:
        raise ActionError("Could not decrypt sigul-pki within 60 seconds") from None
    except OSError:
        raise ActionError(
            "Could not decrypt sigul-pki: cannot run GPG or access its private files"
        ) from None


def kill_gpg_agent(home: Path) -> None:
    """Attempt to stop the private agent without blocking subsequent erasure."""
    try:
        gpgconf = system_tool("gpgconf")
        if gpgconf is None or not home.exists():
            return
        done = capture_text(
            [gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
            env=minimal_env({"HOME": str(home)}),
            timeout=GPGCONF_TIMEOUT_SECONDS,
        )
        if done.returncode != 0:
            warning("gpgconf could not stop gpg-agent; its home is removed regardless")
    except subprocess.TimeoutExpired:
        warning(
            f"gpgconf did not stop gpg-agent within {GPGCONF_TIMEOUT_SECONDS}s; "
            + "its home is removed regardless"
        )
    except OSError:
        warning("could not run gpgconf; its home is removed regardless")
