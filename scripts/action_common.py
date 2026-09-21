#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Helpers shared by the runner-side modules.

Everything under scripts/ except scripts/container/ runs on the
RUNNER, under Python 3.10 or later. scripts/container/ runs inside the
signing container and is held to Python 2.7 as well; see its
container_common.py.
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# Where every tool the action runs is looked up: docker, git, gpg and
# Python itself. Never the job's PATH, to which any earlier step can
# prepend a directory through GITHUB_PATH, so that its own 'docker' or
# 'gpg' would receive the credentials. This is Debian's and Ubuntu's
# default PATH: directories only root can write to, with an
# administrator's /usr/local ahead of the distribution's own, as there.
# action.yaml sets the same value before starting Python.
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Settings a child process may legitimately need from the job's
# environment. Everything else -- secrets, runner tokens, GITHUB_ENV
# and friends -- stays out of the environments built from this.
PASSTHROUGH_VARIABLES = (
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
)


class ActionError(Exception):
    """A failure to report to the caller as a workflow error."""


class InputError(ActionError):
    """The caller's inputs cannot work."""


@dataclass
class Messages:
    """Annotations for the caller, gathered while planning."""

    warnings: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)


def escape_data(value: str) -> str:
    """Escape a value for a workflow command, so a file name or input
    cannot end the command early and inject another."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def error(message: str) -> None:
    """Emit a workflow error annotation."""
    print(f"::error::{escape_data(message)}", flush=True)


def warning(message: str) -> None:
    """Emit a workflow warning annotation."""
    print(f"::warning::{escape_data(message)}", flush=True)


def notice(message: str) -> None:
    """Emit a workflow notice annotation."""
    print(f"::notice::{escape_data(message)}", flush=True)


def info(message: str) -> None:
    """Print a progress line, escaped so it cannot inject a command."""
    print(escape_data(message), flush=True)


def set_output(name: str, value: str) -> None:
    """Write a step output."""
    if "\n" in value or "\r" in value:
        raise ActionError(f"refusing a multi-line value for output {name}")
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            _ = stream.write(f"{name}={value}\n")


def summarise(lines: Sequence[str]) -> None:
    """Append Markdown lines to the job summary."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            _ = stream.write("\n".join(lines) + "\n")


def shred_file(path: Path) -> None:
    """Overwrite a file with zeros, then remove it.

    Every file that held a secret goes this way, never by unlinking
    alone, which leaves the data on disk. Done here rather than by
    shred(1), so it works wherever the action runs. Like shred, it
    cannot reach blocks a copy-on-write or journalling filesystem keeps
    elsewhere. A symlink is removed without following it.
    """
    try:
        status = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(status.st_mode):
        # A bundle can carry read-only files: NSS databases often are.
        # The owner may always restore its own write permission.
        if not status.st_mode & stat.S_IWUSR:
            os.chmod(path, stat.S_IMODE(status.st_mode) | stat.S_IWUSR)
        descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            zeros = memoryview(bytes(65536))
            remaining = status.st_size
            while remaining > 0:
                remaining -= os.write(descriptor, zeros[: min(remaining, len(zeros))])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    path.unlink(missing_ok=True)


def system_tool(name: str) -> str | None:
    """Return the absolute path of a tool in SYSTEM_PATH, or None."""
    return shutil.which(name, path=SYSTEM_PATH)


def minimal_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a clean environment for a child process.

    Children never inherit the job's environment wholesale: it carries
    the action's secret inputs, runner credentials, and variables such
    as GIT_DIR or BASH_ENV that would change what a child does. PATH is
    SYSTEM_PATH, never the job's, and subprocess finds a bare command
    name through the PATH of the environment it is given, so docker,
    git and gpg are only ever the system's.
    """
    env = {
        "PATH": SYSTEM_PATH,
        "LANG": "C",
        "LC_ALL": "C",
    }
    for name in PASSTHROUGH_VARIABLES:
        value = os.environ.get(name)
        if value:
            env[name] = value
    if extra:
        env.update(extra)
    return env
