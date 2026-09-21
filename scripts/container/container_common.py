# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Helpers shared by the scripts that run INSIDE the signing container.

PORTABILITY
===========

Every file in this directory is valid under both Python 2.7 and 3.x.
The legacy client image is CentOS 7 and ships Python 2.7 only; the
modern one is Fedora and ships Python 3 only. One source serves both,
so there is no second implementation to keep in step. That rules out
f-strings, pathlib, ``subprocess.run``, annotations and keyword-only
arguments here; ``.ruff.toml`` and ``pyproject.toml`` record the
exemptions. Retiring the legacy infrastructure lifts the constraint.

Nothing here handles a secret value: the action passes the passphrase
file's PATH, and these scripts only ever redirect it into sigul.
"""

from __future__ import print_function

import os
import pwd
import subprocess
import sys

# The marker sigul's sign-git-tag appends to a tag object. Checking
# for it confirms a signature landed, rather than trusting the exit
# status of a client that may have exited early.
PGP_SIGNATURE_MARKER = "-----BEGIN PGP SIGNATURE-----"


def fail(message):
    """Print to stderr and exit non-zero.

    Raises rather than calling sys.exit() so a reader, and static
    analysis, can see that it never returns.
    """
    print("ERROR: " + message, file=sys.stderr)
    raise SystemExit(1)


def info(message):
    """Print a progress line."""
    print("INFO: " + message)


def warn(message):
    """Print a warning to stderr."""
    print("WARN: " + message, file=sys.stderr)


def require_env(name):
    """Return an environment variable, failing when unset or blank."""
    value = os.environ.get(name, "")
    if not value.strip():
        fail(name + " is required")
    return value


def int_env(name, default):
    """Return a non-negative integer environment variable."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    # Validated rather than caught: wrapping int() needs either a
    # swallowed exception or 'raise ... from', which is Python 3 only.
    if not raw.isdigit():
        fail(name + " must be a non-negative integer, got " + repr(raw))
    return int(raw)


def set_default_user():
    """Give sigul the user name the image would have run as.

    The container runs as the runner's own UID, so that signatures and
    git objects come out owned by the workflow rather than by root.
    That UID has no entry in the image's /etc/passwd, and sigul defaults
    its user-name setting to getpass.getuser(), which then fails --
    KeyError under Python 2, OSError under Python 3 -- before any
    signing starts. getpass consults LOGNAME and USER first, so set
    them to the user the image declares (root when it declares none),
    which is exactly what the client saw when the image ran as itself.
    """
    raw = os.environ.get("SIGUL_DEFAULT_USER", "").split(":", 1)[0].strip()
    name = raw or "root"
    if name.isdigit():
        try:
            name = pwd.getpwuid(int(name)).pw_name
        except KeyError:
            warn("image user " + name + " has no passwd entry; using it as-is")
    os.environ["LOGNAME"] = name
    os.environ["USER"] = name


def read_manifest(path):
    """Return the (source, output) pairs the runner prepared.

    The manifest is NUL-separated, so no file name can be misread.
    Python 2 keeps the raw byte strings, which it accepts as paths;
    Python 3 decodes them as the filesystem does.
    """
    handle = open(path, "rb")
    try:
        data = handle.read()
    finally:
        handle.close()
    fields = data.split(b"\0")
    if fields and not fields[-1]:
        fields = fields[:-1]
    if not fields or len(fields) % 2:
        fail("the signing manifest is empty or malformed: " + path)
    decode = getattr(os, "fsdecode", None)
    if decode is not None:
        fields = [decode(field) for field in fields]
    return [(fields[index], fields[index + 1]) for index in range(0, len(fields), 2)]


def call_with_password(argv, password_file):
    """Run argv with the passphrase file on its stdin; return the status.

    sigul reads the key passphrase from stdin, NUL-terminated.
    """
    handle = open(password_file, "rb")
    try:
        return subprocess.call(argv, stdin=handle)
    finally:
        handle.close()


def git_output(args):
    """Run git; return (status, stripped stdout as text)."""
    process = subprocess.Popen(
        ["git"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, _err = process.communicate()
    if not isinstance(out, str):
        out = out.decode("utf-8", "replace")
    return process.returncode, out.strip()


def remove_if_present(path):
    """Remove a file, ignoring its absence."""
    if os.path.lexists(path):
        os.remove(path)
