#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Decrypt the PKI bundle with gpg, in a private home.

Runs on the RUNNER, under Python 3.10 or later, for
prepare_credentials.py. The private home keeps the runner user's
keyring and agent out of the decryption, and the agent gpg starts for
it is stopped by the caller's cleanup, which then removes the home.

Nothing here prints a credential value.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from action_common import ActionError, minimal_env, system_tool, warning


class UnprotectedBundleError(ActionError):
    """sigul-pki was encrypted without integrity protection."""


# What gpg says, since 2.2.8, of a message without an MDC: the
# modification detection code that GnuPG 2.0 and earlier omitted by
# default with their default cipher, CAST5. Earlier gpg decrypted such
# a message with a warning; the legacy action's CentOS 7 container had
# GnuPG 2.0.22, so a bundle it accepted can be refused here.
_NO_INTEGRITY = ("message was not integrity protected", "decryption forced to fail")

# How long gpgconf gets to stop the agent. Cleanup runs inside the
# seconds the runner allows a cancelled step, so it cannot wait on a
# hung agent; the agent, if any, loses its socket when the home it
# lives in is destroyed next.
GPGCONF_TIMEOUT_SECONDS = 2


def decrypt_bundle(encrypted: Path, passphrase: Path, output: Path, home: Path) -> None:
    """GPG-decrypt the PKI bundle inside a private gpg home.

    --no-symkey-cache stops gpg-agent caching the passphrase. GnuPG 2.1
    and later need --pinentry-mode loopback to take the passphrase from
    a file in batch mode; older releases reject one or both options, so
    each is dropped only when gpg names it as invalid.

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
    absent there is no agent to stop. The wait is bounded, as every
    wait on the way out of a run is.
    """
    gpgconf = system_tool("gpgconf")
    if gpgconf is None or not home.exists():
        return
    try:
        _ = subprocess.run(
            [gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
            capture_output=True,
            env=minimal_env({"HOME": str(home)}),
            check=False,
            timeout=GPGCONF_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        warning(
            f"gpgconf did not stop gpg-agent within {GPGCONF_TIMEOUT_SECONDS}s; "
            + "its home is removed regardless"
        )
