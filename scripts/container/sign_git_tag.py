#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Sign an annotated git tag with Sigul.

Runs INSIDE the signing container, under either Python 2.7 or 3.x
(see container_common.py for why), in a PRIVATE repository the runner
prepared. That repository has clean configuration and keeps its
objects in the workspace's object store (GIT_OBJECT_DIRECTORY), so
sigul's own git calls -- status, show-ref, cat-file, hash-object,
update-ref -- never read the workspace's configuration or hooks, which
the calling job controls and which git can be made to execute code
from. The runner verifies the result, records it in the workspace and
pushes it; this script only signs.

Environment (required unless noted):
  GIT_TAG         tag to sign, already resolved in this repository
  SIGUL_KEY       key name held on the Sigul server
  SIGUL_PASSWORD  path to the passphrase file (NUL-terminated)
  MAX_RETRIES     attempts (optional, default 5)
  RETRY_DELAY     seconds between attempts (optional, default 15)
  ATTEMPT_TIMEOUT seconds an attempt may take, 0 for no limit
                  (optional, default 0)
  EXPECTED_BRIDGE normalized DNS_HOST:PORT guard (optional, empty disables)
"""

from __future__ import print_function

import os
import subprocess
import time

from container_common import (
    TIMED_OUT,
    call_with_password,
    fail,
    git_output,
    info,
    require_env,
    retry_policy,
    set_default_user,
    warn,
)
from tag_integrity import signature_error


def tag_oid(tag):
    """Return the object ID the tag ref points at, failing if absent."""
    status, oid = git_output(["rev-parse", "-q", "--verify", "refs/tags/" + tag])
    if status != 0 or not oid:
        fail("tag does not exist in the signing repository: " + tag)
    return oid


def tag_bytes(oid):
    """Read raw tag bytes; git_output strips whitespace and decodes text."""
    process = subprocess.Popen(
        ["git", "cat-file", "tag", oid], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    body, _error = process.communicate()
    if process.returncode != 0:
        fail("cannot read tag object: " + oid)
    return body


def main():
    set_default_user()
    tag = require_env("GIT_TAG")
    key = require_env("SIGUL_KEY")
    password_file = require_env("SIGUL_PASSWORD")
    retry = retry_policy()
    expected = os.environ.get("EXPECTED_BRIDGE", "")
    if expected:
        from client_configuration import enforce_expected_bridge

        enforce_expected_bridge(expected)

    unsigned = tag_oid(tag)
    status, kind = git_output(["cat-file", "-t", unsigned])
    if status != 0 or kind != "tag":
        fail("{} is not an annotated tag ({})".format(tag, kind or "unreadable"))
    original = tag_bytes(unsigned)
    if not original.endswith(b"\n"):
        fail("the original tag must end with a newline before signing: " + tag)

    info("signing git tag " + tag)
    argv = ["sigul", "--batch", "sign-git-tag", "--", key, tag]
    attempt = 1
    while True:
        status = call_with_password(argv, password_file, retry.timeout)
        current = tag_oid(tag)
        if current != unsigned:
            # A moved ref is never retried: either its exact payload and
            # appended signature are sound, or this run must fail closed.
            problem = signature_error(original, tag_bytes(current))
            if problem:
                fail(problem)
            if status != 0:
                warn("sigul reported failure after updating the tag")
            info("signed git tag {} (attempt {})".format(tag, attempt))
            return 0
        if status == TIMED_OUT:
            warn("sigul did not finish within {}s".format(retry.timeout))
        if attempt >= retry.attempts:
            fail("sign-git-tag failed after {} attempt(s)".format(attempt))
        warn(
            "sign-git-tag failed (attempt {}/{}), retrying in {}s".format(
                attempt, retry.attempts, retry.delay
            )
        )
        time.sleep(retry.delay)
        attempt += 1


if __name__ == "__main__":
    raise SystemExit(main())
