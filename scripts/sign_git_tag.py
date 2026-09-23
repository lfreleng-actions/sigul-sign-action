#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Sign an existing annotated git tag with Sigul.

Runs INSIDE the signing container, on a repository bind-mounted from
the runner. Sigul rewrites the tag object in place, so the signature
lands in the mounted checkout and the caller pushes it afterwards.

This deliberately does NOT push. Pushing is a different privilege,
differs between GitHub and Gerrit, and belongs to the release lane.
global-jjb's release-job.sh couples the two; keeping them apart lets a
verify lane sign a tag with no ability to publish it.

PORTABILITY
===========

Valid under both Python 2.7 and Python 3.x -- see sign_data.py for
why. No f-strings, no pathlib, no subprocess.run, no annotations.

Environment (required unless noted):
  GIT_TAG        name of an existing annotated tag
  SIGUL_CONFIG   path to client.conf
  SIGUL_KEY      key name held on the Sigul server
  SIGUL_PASSWORD path to the passphrase file (NUL-terminated)
  REPO_DIR       repository to operate in (optional, default cwd)
  MAX_RETRIES    attempts (optional, default 5)
  RETRY_DELAY    seconds between attempts (optional, default 15)
"""

from __future__ import print_function

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


def git_output(args):
    """Run git and return (status, stripped stdout)."""
    process = subprocess.Popen(
        ["git"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, _err = process.communicate()
    if not isinstance(out, str):
        out = out.decode("utf-8", "replace")
    return process.returncode, out.strip()


def main():
    tag = require_env("GIT_TAG")
    config = require_env("SIGUL_CONFIG")
    key = require_env("SIGUL_KEY")
    password_file = require_env("SIGUL_PASSWORD")
    max_retries = int_env("MAX_RETRIES", 5)
    retry_delay = int_env("RETRY_DELAY", 15)

    repo_dir = os.environ.get("REPO_DIR", "")
    if repo_dir:
        if not os.path.isdir(repo_dir):
            fail("REPO_DIR is not a directory: " + repo_dir)
        os.chdir(repo_dir)

    # The bind-mounted checkout belongs to the runner user, not the
    # container user. Without this git refuses to touch it at all,
    # with a "dubious ownership" error that reads like a permissions
    # bug rather than a mount one.
    subprocess.call(
        ["git", "config", "--global", "--add", "safe.directory", os.getcwd()]
    )

    status, _ = git_output(["rev-parse", "-q", "--verify", "refs/tags/" + tag])
    if status != 0:
        fail(
            "tag does not exist: {}. Create and verify the tag before "
            "signing it.".format(tag)
        )

    # A lightweight tag points straight at a commit and has no object
    # to carry a signature. Checking here gives a clear reason;
    # leaving it to sigul produces a confusing one.
    status, kind = git_output(["cat-file", "-t", "refs/tags/" + tag])
    if status != 0:
        fail("cannot inspect tag: " + tag)
    if kind != "tag":
        fail(
            "{} is a lightweight tag ({}), not an annotated one. Only "
            "annotated tags can carry a signature.".format(tag, kind)
        )

    print("INFO: signing git tag '{}' with key '{}'".format(tag, key))

    argv = ["sigul", "--batch", "-c", config, "sign-git-tag", key, tag]
    attempt = 1
    while True:
        handle = open(password_file, "rb")
        try:
            status = subprocess.call(argv, stdin=handle)
        finally:
            handle.close()

        if status == 0:
            print("INFO: signed git tag '{}' (attempt {})".format(tag, attempt))
            return 0
        if attempt >= max_retries:
            fail("sign-git-tag failed after {} attempts".format(max_retries))
        print(
            "WARN: sign-git-tag failed (attempt {}/{}), retrying in {}s...".format(
                attempt, max_retries, retry_delay
            ),
            file=sys.stderr,
        )
        time.sleep(retry_delay)
        attempt += 1


if __name__ == "__main__":
    sys.exit(main())
