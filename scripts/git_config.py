# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Read workspace Git settings without entering or executing its configuration."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from action_common import ActionError, minimal_env
from process_control import capture_bytes


def git_env(home: Path, objects: Path | None = None) -> dict[str, str]:
    """Return an environment for git that reads no caller configuration."""
    extra = {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if objects is not None:
        extra["GIT_OBJECT_DIRECTORY"] = str(objects)
    return minimal_env(extra)


def _read_config(git_dir: Path) -> dict[bytes, bytes]:
    """Use Git's parser on one explicit file, never following includes.

    Section and variable names arrive Git-normalized; subsection names do not.
    NUL records preserve embedded newlines, and the last occurrence wins.
    """
    config = (git_dir / "config").absolute()
    if not config.exists() and not config.is_symlink():
        return {}
    with tempfile.TemporaryDirectory(prefix="sigul-git-config.") as scratch:
        home = Path(scratch)
        env = git_env(home)
        env["GIT_CEILING_DIRECTORIES"] = str(home)
        try:
            done = capture_bytes(
                [
                    "git",
                    "config",
                    "--null",
                    "--list",
                    "--file",
                    str(config),
                    "--no-includes",
                ],
                cwd=home,
                env=env,
            )
        except FileNotFoundError:
            raise ActionError("git is not installed on the runner") from None
    if done.returncode != 0:
        # Git's diagnostics can quote untrusted configuration, including secrets.
        raise ActionError("cannot parse the workspace's .git/config")
    values: dict[bytes, bytes] = {}
    for record in done.stdout.split(b"\0"):
        if not record:
            continue
        key, _, value = record.partition(b"\n")
        if key == b"include.path" or (
            key.startswith(b"includeif.") and key.endswith(b".path")
        ):
            raise ActionError(
                "includes in the workspace's .git/config are not supported"
            )
        values[key] = value
    return values


def read_extension(git_dir: Path, name: str) -> str:
    """Return a parsed extension value lower-cased, or '' when unset."""
    values = _read_config(git_dir)
    value = values.get(b"extensions." + name.lower().encode("utf-8"), b"")
    return value.decode("utf-8", "surrogateescape").lower()


def _uses_format(git_dir: Path, key: bytes, supported: tuple[bytes, bytes]) -> bool:
    """Classify an explicit format or its default, refusing unknown values.

    Git normalizes keys, but these format names are case-sensitive. Only a
    missing key selects the default; empty, bare, or misspelled values do not.
    """
    value = _read_config(git_dir).get(key, supported[0])
    if value not in supported:
        raise ActionError(
            f"unsupported {key.decode('ascii')} in the workspace's .git/config"
        )
    return value == supported[1]


def uses_sha256(git_dir: Path) -> bool:
    """Return True for SHA-256, False for SHA-1; reject any other object format."""
    return _uses_format(git_dir, b"extensions.objectformat", (b"sha1", b"sha256"))


def uses_reftable(git_dir: Path) -> bool:
    """Return True for reftables, False for files; reject any other ref storage."""
    return _uses_format(git_dir, b"extensions.refstorage", (b"files", b"reftable"))
