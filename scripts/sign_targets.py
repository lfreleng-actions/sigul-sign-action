#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Resolve sign-object into the files to sign, for sign-data.

Runs on the RUNNER, under Python 3.10 or later, before any credential
exists. The container is only ever told which files to sign and where
each signature goes; every decision is made here, where it is tested.

The rules are lfit/sigul-sign-action's, extended in one direction:

  * one entry per line, blank lines skipped;
  * a line containing '*' is split into words and each expanded as a
    shell wildcard, keeping the regular files it matches -- a symlink
    to one included -- and warning when a line matches nothing;
  * any other line names a regular file or, beyond the legacy action,
    a directory, signed recursively as global-jjb's sigul-sign-dir.sh
    signed one: regular files only, less the exclusions;
  * every path resolves inside the workspace, the only directory the
    legacy action's container could reach, and any problem fails the
    run before anything is signed.
"""

from __future__ import annotations

import fnmatch
import os
import re
import stat
from dataclasses import dataclass, field
from glob import glob
from pathlib import Path

from action_common import InputError, Messages

# Where the legacy Docker action mounted the workspace. An absolute
# sign-object entry written against it still names the same file.
LEGACY_WORKSPACE = "/github/workspace"

_GLOB_MAGIC = re.compile(r"[*?[]")


@dataclass(frozen=True)
class SignTarget:
    """A file to sign, and where its signature goes."""

    source: str
    output: str

    @property
    def name(self) -> str:
        """The file as the caller named it: beside a symlink, not its
        target, which is where its signature goes."""
        return self.output.removesuffix(".asc")


def _within(path: str, root: str) -> bool:
    return os.path.commonpath([path, root]) == root


@dataclass
class _Collector:
    """Accumulates targets in order, without duplicates."""

    workspace: str
    real_workspace: str
    targets: dict[str, SignTarget] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def absolute(self, entry: str) -> str:
        if entry == LEGACY_WORKSPACE or entry.startswith(LEGACY_WORKSPACE + "/"):
            entry = self.workspace + entry[len(LEGACY_WORKSPACE) :]
        # Resolve symlinks before collapsing '..'; lexical cleanup changes its meaning.
        return os.path.join(self.workspace, entry)

    def add_file(self, path: str, entry: str) -> None:
        """Add a regular file, or a symlink to one inside the workspace.

        The signature goes beside the name given, as the legacy action
        wrote it -- beside a symlink rather than its target.
        """
        real = os.path.realpath(path)
        if not _within(real, self.real_workspace):
            self.errors.append(
                f"{entry} resolves outside the workspace ({real}); only files "
                + "in the workspace can be signed"
            )
            return
        if not stat.S_ISREG(os.stat(real).st_mode):
            self.errors.append(f"Not a regular file: {entry}")
            return
        directory = os.path.realpath(os.path.dirname(path))
        if not _within(directory, self.real_workspace):
            # Only the workspace is mounted: a signature written anywhere
            # else would vanish with the container.
            self.errors.append(
                f"{entry} lies outside the workspace ({directory}), where its "
                + "signature could not be written"
            )
            return
        output = os.path.join(directory, os.path.basename(path) + ".asc")
        if os.path.isdir(output):
            self.errors.append(f"cannot write a signature over the directory {output}")
            return
        _ = self.targets.setdefault(output, SignTarget(source=real, output=output))

    def add_directory(self, path: str, entry: str, excludes: list[str]) -> None:
        """Add every regular file beneath a directory: 'find -type f',
        less the exclusions. Symlinks are not followed and special files
        are skipped, so nothing outside the tree is signed and no FIFO
        blocks sigul."""
        real = os.path.realpath(path)
        if not _within(real, self.real_workspace):
            self.errors.append(f"{entry} resolves outside the workspace ({real})")
            return

        def on_error(exc: OSError) -> None:
            self.errors.append(f"cannot read part of {entry}: {exc}")

        for directory, subdirectories, files in os.walk(real, onerror=on_error):
            subdirectories.sort()
            for name in sorted(files):
                if any(fnmatch.fnmatchcase(name, pattern) for pattern in excludes):
                    continue
                candidate = os.path.join(directory, name)
                if not stat.S_ISREG(os.lstat(candidate).st_mode):
                    continue
                output = candidate + ".asc"
                if os.path.isdir(output):
                    self.errors.append(
                        f"cannot write a signature over the directory {output}"
                    )
                    continue
                _ = self.targets.setdefault(output, SignTarget(candidate, output))

    def add_wildcard_line(self, line: str, messages: Messages) -> None:
        """Expand each word of a line containing '*', as the shell did."""
        matched = 0
        for word in line.split():
            pattern = self.absolute(word)
            if _GLOB_MAGIC.search(word):
                paths = sorted(glob(pattern))
            else:
                paths = [pattern] if os.path.lexists(pattern) else []
            for path in paths:
                if os.path.isfile(path):
                    matched += 1
                    self.add_file(path, path)
        if not matched:
            messages.warnings.append(f"No regular files match: {line}")

    def add_entry(self, line: str, excludes: list[str]) -> None:
        """Add a file, or a directory's files."""
        path = self.absolute(line)
        if os.path.isdir(path):
            if os.path.islink(path):
                self.errors.append(
                    f"{line} is a symlink to a directory; name the directory itself"
                )
            else:
                self.add_directory(path, line, excludes)
        elif os.path.isfile(path):
            self.add_file(path, line)
        else:
            self.errors.append(f"Not a regular file or directory: {line}")


def _crosses_output(path: str, outputs: set[str]) -> bool:
    """Follow every file symlink, checking each name before dereferencing it.

    Resolve only parents at each hop: resolving the whole path would hide an
    intermediate stale signature. Planned outputs cannot be directories, so
    none can be skipped by resolving a parent. Repeated links indicate a cycle.
    """
    seen: set[str] = set()
    while True:
        parent, name = os.path.split(path)
        path = os.path.join(os.path.realpath(parent), name)
        if path in outputs:
            return True
        if path in seen:
            raise InputError(f"Symlink cycle while resolving {path}")
        seen.add(path)
        if not os.path.islink(path):
            return False
        path = os.path.join(os.path.dirname(path), os.readlink(path))


def plan_sign_data(
    sign_object: str, workspace: Path, excludes: list[str], messages: Messages
) -> tuple[SignTarget, ...]:
    """Resolve sign-object into the files to sign, or fail with every
    problem found."""
    collector = _Collector(str(workspace), os.path.realpath(workspace))
    for raw in sign_object.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "*" in line:
            collector.add_wildcard_line(line, messages)
        else:
            collector.add_entry(line, excludes)

    if collector.errors:
        raise InputError("\n".join(collector.errors))

    # Keep the full output set, even for candidates filtered out below:
    # a source depending on any planned replacement is not an artefact.
    outputs = set(collector.targets)
    targets = tuple(
        t for t in collector.targets.values() if not _crosses_output(t.name, outputs)
    )
    if not targets:
        raise InputError("No files to sign; check sign-object")
    return targets
