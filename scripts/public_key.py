#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Check the connection: retrieve the signing key's public key, sign nothing.

Runs on the RUNNER, under Python 3.10 or later. The reply comes out of
the client container, so it is treated as untrusted: read without
following a link, bounded in size, required to be exactly one
ASCII-armoured public key block, and parsed by gpg --show-keys in the
action's private GnuPG home, never the runner's keyring. Nothing is
imported anywhere.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

from action_common import (
    ActionError,
    info,
    markdown_code,
    minimal_env,
    set_output,
    summarise,
)
from client_container import (
    CONTAINER_CREDS,
    ContainerRun,
    bind,
    container_argv,
    run_container,
)
from credential_files import write_private
from process_control import capture_text

# Where, under the credentials directory, check-connection's reply goes.
PUBLIC_KEY_FILE = "public-key"

ARMOUR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
ARMOUR_END = "-----END PGP PUBLIC KEY BLOCK-----"
# A public key with a few subkeys and signatures is a few KiB; this
# leaves room for many more without reading whatever a client prints.
MAX_PUBLIC_KEY_BYTES = 1024 * 1024
GPG_TIMEOUT_SECONDS = 60
# v4 fingerprints are 40 hex digits, v5 and v6 are 64.
_FINGERPRINT = re.compile(r"[0-9A-F]{40}|[0-9A-F]{64}")

_NOT_A_PUBLIC_KEY = (
    "the server's reply is not exactly one ASCII-armoured PGP PUBLIC KEY BLOCK"
)


def read_reply(path: Path) -> bytes:
    """Read the reply the container wrote, refusing a link or special file."""
    try:
        # O_NONBLOCK: a FIFO in place of the reply would otherwise block
        # this open until a writer appears, outside every timeout the
        # action sets. It changes nothing for a regular file, and the
        # fstat below refuses anything else.
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        )
    except OSError:
        raise ActionError("the connection check returned no public key") from None
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ActionError("the connection check's reply is not a regular file")
        data = stream.read(MAX_PUBLIC_KEY_BYTES + 1)
    if len(data) > MAX_PUBLIC_KEY_BYTES:
        raise ActionError(f"{_NOT_A_PUBLIC_KEY}: it exceeds 1 MiB")
    return data


def check_armour(data: bytes) -> None:
    """Require one armoured public key block, and nothing around it."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ActionError(f"{_NOT_A_PUBLIC_KEY}: it is not ASCII") from None
    lines = [line.rstrip() for line in text.strip().splitlines()]
    if (
        len(lines) < 3
        or lines[0] != ARMOUR_BEGIN
        or lines[-1] != ARMOUR_END
        or any(line.startswith("-----") for line in lines[1:-1])
    ):
        raise ActionError(_NOT_A_PUBLIC_KEY)


def fingerprints_from_colons(listing: str) -> list[str]:
    """Return the primary key's fingerprint, then each subkey's, from
    gpg --with-colons output describing exactly one public key."""
    fingerprints: list[str] = []
    keys = 0
    awaiting = False
    for line in listing.splitlines():
        fields = line.split(":")
        record = fields[0]
        if record in ("sec", "ssb"):
            raise ActionError(f"{_NOT_A_PUBLIC_KEY}: it holds secret key material")
        if record in ("pub", "sub"):
            if awaiting or (record == "pub") != (keys == 0):
                raise ActionError(f"{_NOT_A_PUBLIC_KEY}: it is not one key")
            keys += 1
            awaiting = True
        elif record == "fpr" and awaiting:
            value = fields[9].upper() if len(fields) > 9 else ""
            if not _FINGERPRINT.fullmatch(value):
                raise ActionError(f"{_NOT_A_PUBLIC_KEY}: a fingerprint is malformed")
            fingerprints.append(value)
            awaiting = False
    if keys == 0 or awaiting:
        raise ActionError(f"{_NOT_A_PUBLIC_KEY}: gpg lists no complete key")
    return fingerprints


def public_key_fingerprints(path: Path, home: Path) -> list[str]:
    """Validate the reply at path; return its fingerprints, primary first.

    home is a private, empty GnuPG home the caller owns and removes.
    """
    data = read_reply(path)
    check_armour(data)
    # A copy the container cannot reach, so gpg reads what was checked.
    checked = home / "public-key.asc"
    write_private(checked, data)
    try:
        done = capture_text(
            [
                "gpg",
                "--homedir",
                str(home),
                "--batch",
                "--no-tty",
                "--with-colons",
                "--with-subkey-fingerprint",
                "--show-keys",
                str(checked),
            ],
            env=minimal_env({"HOME": str(home)}),
            timeout=GPG_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise ActionError(
            f"gpg did not read the public key within {GPG_TIMEOUT_SECONDS} seconds"
        ) from None
    except OSError:
        raise ActionError("cannot run gpg to read the public key") from None
    if done.returncode != 0:
        raise ActionError(f"{_NOT_A_PUBLIC_KEY}: gpg cannot read it")
    return fingerprints_from_colons(done.stdout)


def check_connection(run: ContainerRun, gnupg: Path) -> None:
    """Retrieve the signing key's public key, signing nothing.

    The workspace is mounted read-only and the reply lands in the
    private credentials directory. gnupg is the path of the private
    GnuPG home that decrypted the bundle, removed since; it is made
    again, empty, for gpg to read the reply in, and cleanup removes it.
    """
    plan = run.plan
    workspace = os.path.realpath(plan.workspace)
    argv = container_argv(
        run,
        [bind(workspace, workspace, readonly=True)],
        {
            "PUBLIC_KEY_FILE": f"{CONTAINER_CREDS}/{PUBLIC_KEY_FILE}",
            # The container stops a reply at this size as it streams,
            # so read_reply's bound is never the first one reached.
            "PUBLIC_KEY_LIMIT": str(MAX_PUBLIC_KEY_BYTES),
        },
        workspace,
        "get_public_key.py",
    )
    if run_container(argv, run.name, None) != 0:
        raise ActionError(
            "The connection check failed; the container's output above says why"
        )
    try:
        gnupg.mkdir(mode=0o700)
    except OSError as exc:
        raise ActionError(
            f"cannot create a private GnuPG home ({exc.strerror or exc.errno})"
        ) from None
    fingerprints = public_key_fingerprints(run.creds / PUBLIC_KEY_FILE, gnupg)
    set_output("signed_count", "0")
    set_output("public_key_fingerprints", " ".join(fingerprints))
    info(
        f"Connection check passed: public key {fingerprints[0]}, "
        + f"{len(fingerprints) - 1} subkey(s); nothing was signed"
    )
    summarise(
        [
            "### Sigul connection check passed ✅",
            "",
            "Retrieved the signing key's public key; nothing was signed.",
            "",
            *(f"- {markdown_code(fingerprint)}" for fingerprint in fingerprints),
        ]
    )
