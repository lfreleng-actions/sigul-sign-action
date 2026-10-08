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
import re
import shutil
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# Where every tool the action runs is looked up: docker, git, gpg and
# Python itself. Never the job's PATH, to which any earlier step can
# prepend a directory through GITHUB_PATH, so that its own 'docker' or
# 'gpg' would receive the credentials. This is Debian's and Ubuntu's
# default PATH, with an administrator's /usr/local ahead of the
# distribution's own, as there. Its directories are usually root's
# alone, but not always: GitHub-hosted Ubuntu runners make
# /usr/local/bin world-writable, so an earlier step can plant a tool
# there with no privilege at all. check_runtime() therefore refuses a
# tool found in a directory the runner's user, or anyone, can write
# to, and action.yaml makes the same check before starting Python.
#
# None of this is a boundary between steps. Every step of a job runs
# as one user, on GitHub-hosted runners one with passwordless sudo, so
# a hostile earlier step can always win; these checks stop an earlier
# step from redirecting the action by accident, and turn a planted tool
# into a loud failure rather than a silent leak.
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
    """Render progress as data for both runner command syntaxes."""
    rendered = escape_data(message).replace("##[", "##%5B")
    print("INFO: " + rendered, flush=True)


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


def markdown_code(value: str) -> str:
    """Return value as a Markdown code span that it cannot break out of.

    A file name is the caller's, and may carry backticks or line breaks.
    A code span is delimited by a run of backticks longer than any run
    inside it, and cannot span a paragraph, so line breaks become
    spaces.
    """
    flat = " ".join(value.splitlines()) or value
    runs: list[str] = re.findall(r"`+", flat)
    longest = max((len(run) for run in runs), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {flat} {fence}" if longest else f"`{flat}`"


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


def is_untrusted_directory(directory: str) -> bool:
    """Return True when an earlier step of the job could write here.

    World-writable is untrusted outright. Short of that, 'writable'
    means by the user this process runs as, because every other step
    of the job runs as that same user. Root can write anywhere, so for
    root only the mode bits say anything.
    """
    status = os.stat(directory)
    if status.st_mode & stat.S_IWOTH:
        return True
    if os.geteuid() == 0:
        return False
    return os.access(directory, os.W_OK)


def check_trusted_location(path: str) -> None:
    """Fail unless path, and whatever it resolves to, lie in directories
    an earlier step of the job could not have written to."""
    for directory in sorted(
        {os.path.dirname(path), os.path.dirname(os.path.realpath(path))}
    ):
        if is_untrusted_directory(directory):
            raise ActionError(
                f"refusing {path}: {directory} is writable by the user running "
                + "this job, so an earlier step could have planted it; install "
                + "the tool in a directory only root can write to"
            )


def system_tool(name: str) -> str | None:
    """Return the absolute path of a tool in SYSTEM_PATH, or None.

    Whether that path can be trusted is check_trusted_location's
    question, asked by check_runtime before anything runs.
    """
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
