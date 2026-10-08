#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Sign the files the runner listed, with Sigul.

Runs INSIDE the signing container, never on the runner, under either
Python 2.7 or 3.x (see container_common.py for why).

The runner has already decided WHAT to sign -- expanded wildcards,
walked directories, applied exclusions, resolved symlinks and checked
everything sits inside the workspace -- and cleared any signature left
by an earlier run. This script only signs, one manifest entry at a
time, writing each signature where the manifest says.

Each file is retried, since the client crosses a network to the
bridge. A file that exhausts its retries stops the run: the step
fails, and no signature is left behind for that file.

Environment (required unless noted):
  MANIFEST        NUL-separated source/output path pairs
  SIGUL_KEY       key name held on the Sigul server
  SIGUL_PASSWORD  path to the passphrase file (NUL-terminated)
  MAX_RETRIES     attempts per file (optional, default 5)
  RETRY_DELAY     seconds between attempts (optional, default 15)
  ATTEMPT_TIMEOUT seconds an attempt may take, 0 for no limit
                  (optional, default 0)
  COUNT_FILE      where to record how many files were signed (optional)
"""

from __future__ import print_function

import os
import time

from container_common import (
    TIMED_OUT,
    call_with_password,
    fail,
    info,
    read_manifest,
    remove_if_present,
    require_env,
    retry_policy,
    set_default_user,
    warn,
)


def produced_signature(path):
    """Return True when sigul left a non-empty file at path."""
    return os.path.isfile(path) and os.path.getsize(path) > 0


def sign_one(source, output, key, password_file, retry):
    """Sign one file, retrying transient failures as retry says."""
    # '--' ends option parsing, so a key or file name starting with a
    # dash cannot be read as an option.
    argv = ["sigul", "--batch", "sign-data", "-a", "-o", output, "--", key, source]
    attempt = 1
    while True:
        # Start each attempt clean. sigul hard-links an existing output
        # to '<output>~' before replacing it, and a failed attempt must
        # not leave a partial or stale signature in place.
        remove_if_present(output)
        status = call_with_password(argv, password_file, retry.timeout)
        if status == 0 and produced_signature(output):
            # sigul writes through mkstemp, so the file arrives 0600;
            # the legacy action published signatures world-readable.
            os.chmod(output, 0o644)
            return
        if status == 0:
            warn("sigul exited zero but wrote no signature: " + output)
        elif status == TIMED_OUT:
            warn("sigul did not finish within {}s: {}".format(retry.timeout, source))
        if attempt >= retry.attempts:
            remove_if_present(output)
            fail("signing failed after {} attempt(s): {}".format(attempt, source))
        warn(
            "signing failed (attempt {}/{}), retrying in {}s: {}".format(
                attempt, retry.attempts, retry.delay, source
            )
        )
        time.sleep(retry.delay)
        attempt += 1


def main():
    set_default_user()
    manifest = require_env("MANIFEST")
    key = require_env("SIGUL_KEY")
    password_file = require_env("SIGUL_PASSWORD")
    retry = retry_policy()
    count_file = os.environ.get("COUNT_FILE", "")

    pairs = read_manifest(manifest)
    info("signing {} file(s)".format(len(pairs)))

    signed = 0
    for source, output in pairs:
        # Named by where the signature goes, so a symlink is reported as
        # the name the caller gave rather than as its target.
        info("signing " + output[: -len(".asc")])
        sign_one(source, output, key, password_file, retry)
        signed += 1
        if count_file:
            # Recorded as it goes, so a failed run still reports how far
            # it got.
            handle = open(count_file, "w")
            try:
                handle.write("{}\n".format(signed))
            finally:
                handle.close()

    info("signed {} file(s)".format(signed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
