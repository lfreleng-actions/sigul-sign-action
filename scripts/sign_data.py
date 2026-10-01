#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Sign a file or a directory tree with Sigul.

Runs INSIDE the signing container, never on the runner.

PORTABILITY
===========

Valid under both Python 2.7 and Python 3.x, deliberately. The legacy
Sigul image is CentOS 7 and ships Python 2.7 only; the containerised
1.4 stack is Fedora-based and ships Python 3. One source file serves
both, so there is no second implementation to keep in step, and when
the legacy infrastructure retires the only change needed is deleting
the ``__future__`` import below.

That constrains the style: no f-strings, no pathlib, no
``subprocess.run``, no annotations. Please keep it that way while the
legacy backend is in use.

Replaces global-jjb's shell/sigul-sign.sh, with three differences:

  * The exclusion list is an input rather than a hardcoded set of
    Maven bookkeeping names, so the action is not Maven-only.
  * Failures retry. The client crosses a network to the bridge and a
    transient error should not fail a release.
  * Traversal errors are fatal. The shell original enumerated with
    ``find`` inside a process substitution, whose exit status is
    discarded: an unreadable subtree meant signing a partial list and
    exiting zero.

Environment (required unless noted):
  SIGN_TARGET    file or directory to sign
  SIGUL_CONFIG   path to client.conf
  SIGUL_KEY      key name held on the Sigul server
  SIGUL_PASSWORD path to the passphrase file (NUL-terminated)
  EXCLUDE_GLOBS  newline-separated fnmatch patterns (optional)
  MAX_RETRIES    attempts per file (optional, default 5)
  RETRY_DELAY    seconds between attempts (optional, default 15)
  COUNT_FILE     path to write the number of files signed (optional)
"""

from __future__ import print_function

import fnmatch
import os
import subprocess
import sys
import time


def fail(message):
    """Print to stderr and exit non-zero.

    Raises rather than calling sys.exit() so static analysis can see
    that this never returns, which in turn lets callers treat the
    helpers below as always producing a value.
    """
    print("ERROR: " + message, file=sys.stderr)
    raise SystemExit(1)


def require_env(name):
    """Return an environment variable, failing when unset or empty."""
    value = os.environ.get(name, "")
    if not value.strip():
        fail(name + " is required")
    return value


def int_env(name, default):
    """Return an integer environment variable with a default."""
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    # Validated rather than caught. Wrapping int() in try/except
    # needs either a bare "pass" -- a swallowed exception -- or
    # "raise ... from err", which is Python 3 syntax these files
    # cannot use. Checking the string first avoids both.
    value = raw.strip()
    if not value.isdigit():
        fail(name + " must be a non-negative integer, got " + repr(raw))
        raise SystemExit(1)
    return int(value)


def load_excludes():
    """Return the newline-separated exclusion patterns as a list."""
    raw = os.environ.get("EXCLUDE_GLOBS", "")
    return [line.strip() for line in raw.splitlines() if line.strip()]


def collect_files(target, excludes):
    """Return the files to sign beneath target.

    A traversal error is fatal rather than skipped. Signing a partial
    tree and reporting success would publish a release whose artefacts
    are only partly signed, which is worse than failing.
    """
    if os.path.isfile(target):
        # An explicit file target is still checked: a symlink here
        # would sign whatever it points at, which the caller may not
        # have intended.
        if os.path.islink(target):
            fail("SIGN_TARGET is a symlink; pass the real path: " + target)
        return [target]

    def on_error(error):
        fail("cannot read {}: {}".format(getattr(error, "filename", "?"), error))

    files = []
    for dirpath, _dirnames, filenames in os.walk(target, onerror=on_error):
        for name in sorted(filenames):
            if any(fnmatch.fnmatch(name, pattern) for pattern in excludes):
                continue
            path = os.path.join(dirpath, name)
            # os.walk puts every non-directory entry in filenames:
            # symlinks, FIFOs, sockets and device nodes among them.
            # A FIFO would block sigul indefinitely, and a symlink
            # would sign whatever it points at -- possibly outside
            # the tree the caller asked for. Sign regular files only,
            # and do not follow links to reach them.
            if os.path.islink(path) or not os.path.isfile(path):
                print(
                    "INFO: skipping non-regular file: " + path,
                    file=sys.stderr,
                )
                continue
            files.append(path)
    return sorted(files)


def sign_one(path, config, key, password_file, max_retries, retry_delay):
    """Sign one file, retrying transient failures."""
    argv = [
        "sigul",
        "--batch",
        "-c",
        config,
        "sign-data",
        "-a",
        "-o",
        path + ".asc",
        key,
        path,
    ]
    attempt = 1
    while True:
        # Sigul reads the NUL-terminated passphrase from stdin.
        handle = open(password_file, "rb")
        try:
            status = subprocess.call(argv, stdin=handle)
        finally:
            handle.close()

        if status == 0:
            return
        if attempt >= max_retries:
            fail("signing failed after {} attempts: {}".format(max_retries, path))
        print(
            "WARN: signing failed (attempt {}/{}), retrying in {}s: {}".format(
                attempt, max_retries, retry_delay, path
            ),
            file=sys.stderr,
        )
        time.sleep(retry_delay)
        attempt += 1


def main():
    target = require_env("SIGN_TARGET")
    config = require_env("SIGUL_CONFIG")
    key = require_env("SIGUL_KEY")
    password_file = require_env("SIGUL_PASSWORD")
    max_retries = int_env("MAX_RETRIES", 5)
    retry_delay = int_env("RETRY_DELAY", 15)
    count_file = os.environ.get("COUNT_FILE", "")

    if not os.path.exists(target):
        fail("SIGN_TARGET does not exist: " + target)

    excludes = load_excludes()
    files = collect_files(target, excludes)

    if not files:
        # Deliberately fatal. A signing step that signs nothing and
        # exits zero produces an unsigned release that looks signed.
        message = "no files to sign under " + target
        if excludes:
            message += " (every candidate matched an exclusion)"
        fail(message)

    print("INFO: signing {} file(s) with key '{}'".format(len(files), key))

    signed = 0
    for path in files:
        sign_one(path, config, key, password_file, max_retries, retry_delay)
        signed += 1

    print("INFO: signed {} file(s)".format(signed))

    if count_file:
        handle = open(count_file, "w")
        try:
            handle.write("{}\n".format(signed))
        finally:
            handle.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
