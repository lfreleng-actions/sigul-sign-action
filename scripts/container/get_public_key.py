#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Check the connection: fetch the signing key's public key from Sigul.

Runs INSIDE the signing container, under either Python 2.7 or 3.x
(see container_common.py for why), with the same mounts, user, hosts
entries and environment a signing run gets, the workspace read-only.

'sigul get-public-key' without --password sends the KEY PASSPHRASE,
which the server checks against the user's access to the key, so a
reply proves the client reached the bridge, the bridge reached the
server, and the passphrase still authorises the user's access to the
key. It does not prove the server can sign: the server answers from
the key's public half, never touching the secret one. Nothing is
signed.

The reply is written to PUBLIC_KEY_FILE, under the credentials mount,
never the workspace, and never to the log. It is capped at
PUBLIC_KEY_LIMIT bytes while it streams, the size the runner accepts:
a reply over the cap stops the client at once and fails without a
retry, since the next attempt would stream the same key. The runner
checks that the reply is one ASCII-armoured public key and reports
its fingerprints.

Environment (required unless noted):
  SIGUL_KEY        key name held on the Sigul server
  SIGUL_PASSWORD   path to the passphrase file (NUL-terminated)
  PUBLIC_KEY_FILE  where to write the armoured public key
  PUBLIC_KEY_LIMIT the most bytes the reply may hold (optional,
                   default 1048576)
  MAX_RETRIES      attempts (optional, default 5)
  RETRY_DELAY      seconds between attempts (optional, default 15)
  ATTEMPT_TIMEOUT  seconds an attempt may take, 0 for no limit
                   (optional, default 0)
  EXPECTED_BRIDGE  normalized DNS_HOST:PORT guard (optional, empty
                   disables)
"""

from __future__ import print_function

import os
import time

from container_common import (
    TIMED_OUT,
    TOO_LARGE,
    call_with_password,
    fail,
    info,
    int_env,
    remove_if_present,
    require_env,
    retry_policy,
    set_default_user,
    warn,
)

# The runner's own cap, for when the variable is absent.
DEFAULT_LIMIT = 1024 * 1024


def fetch_once(argv, password_file, output, timeout, limit):
    """Run one attempt, its output going to a new, private file, capped."""
    # Start each attempt clean, so a failed one leaves nothing behind
    # that a later step could take for the reply.
    remove_if_present(output)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    handle = os.fdopen(os.open(output, flags, 0o600), "wb")
    try:
        return call_with_password(
            argv, password_file, timeout, stdout=handle, limit=limit
        )
    finally:
        handle.close()


def main():
    set_default_user()
    key = require_env("SIGUL_KEY")
    password_file = require_env("SIGUL_PASSWORD")
    output = require_env("PUBLIC_KEY_FILE")
    limit = int_env("PUBLIC_KEY_LIMIT", DEFAULT_LIMIT)
    if limit < 1:
        fail("PUBLIC_KEY_LIMIT must be at least 1")
    retry = retry_policy()
    expected = os.environ.get("EXPECTED_BRIDGE", "")
    if expected:
        from client_configuration import enforce_expected_bridge

        enforce_expected_bridge(expected)

    info("retrieving the signing key's public key; nothing is signed")
    # '--' ends option parsing, so a key name starting with a dash
    # cannot be read as an option. No --password: see above.
    argv = ["sigul", "--batch", "get-public-key", "--", key]
    attempt = 1
    while True:
        status = fetch_once(argv, password_file, output, retry.timeout, limit)
        if status == 0 and os.path.getsize(output) > 0:
            info("retrieved the public key (attempt {})".format(attempt))
            return 0
        if status == TOO_LARGE:
            # Not transient: the next attempt would stream the same key.
            remove_if_present(output)
            fail("the server's reply exceeds {} bytes".format(limit))
        if status == 0:
            warn("sigul exited zero but returned no public key")
        elif status == TIMED_OUT:
            warn("sigul did not finish within {}s".format(retry.timeout))
        if attempt >= retry.attempts:
            remove_if_present(output)
            fail("get-public-key failed after {} attempt(s)".format(attempt))
        warn(
            "get-public-key failed (attempt {}/{}), retrying in {}s".format(
                attempt, retry.attempts, retry.delay
            )
        )
        time.sleep(retry.delay)
        attempt += 1


if __name__ == "__main__":
    raise SystemExit(main())
