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
"""

from __future__ import print_function

import time

from container_common import (
    PGP_SIGNATURE_MARKER,
    call_with_password,
    fail,
    git_output,
    info,
    int_env,
    require_env,
    set_default_user,
    warn,
)


def tag_oid(tag):
    """Return the object ID the tag ref points at, failing if absent."""
    status, oid = git_output(["rev-parse", "-q", "--verify", "refs/tags/" + tag])
    if status != 0 or not oid:
        fail("tag does not exist in the signing repository: " + tag)
    return oid


def main():
    set_default_user()
    tag = require_env("GIT_TAG")
    key = require_env("SIGUL_KEY")
    password_file = require_env("SIGUL_PASSWORD")
    max_retries = int_env("MAX_RETRIES", 5)
    retry_delay = int_env("RETRY_DELAY", 15)
    if max_retries < 1:
        fail("MAX_RETRIES must be at least 1")

    unsigned = tag_oid(tag)
    status, kind = git_output(["cat-file", "-t", unsigned])
    if status != 0 or kind != "tag":
        fail("{} is not an annotated tag ({})".format(tag, kind or "unreadable"))

    info("signing git tag " + tag)
    argv = ["sigul", "--batch", "sign-git-tag", "--", key, tag]
    attempt = 1
    while True:
        status = call_with_password(argv, password_file)
        current = tag_oid(tag)
        if current != unsigned:
            # sigul moved the ref, so the signature landed. Retrying now
            # would sign the signed object again and append a second
            # signature, so stop even if sigul reported an error after
            # its final update-ref.
            if status != 0:
                warn("sigul reported failure after updating the tag")
            _status, body = git_output(["cat-file", "tag", current])
            if PGP_SIGNATURE_MARKER not in body:
                fail("the tag changed but carries no signature")
            info("signed git tag {} (attempt {})".format(tag, attempt))
            return 0
        if attempt >= max_retries:
            fail("sign-git-tag failed after {} attempt(s)".format(attempt))
        warn(
            "sign-git-tag failed (attempt {}/{}), retrying in {}s".format(
                attempt, max_retries, retry_delay
            )
        )
        time.sleep(retry_delay)
        attempt += 1


if __name__ == "__main__":
    raise SystemExit(main())
