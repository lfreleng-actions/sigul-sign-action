# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/container/container_common.py's process handling.

Those scripts are held to Python 2.7 as well as 3, and import nothing
from the runner side, so they are imported here directly. The
end-to-end job runs them under each image's own Python.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast
from unittest import mock

from tests.helpers import REPOSITORY, scratch

CONTAINER = REPOSITORY / "scripts" / "container"
if str(CONTAINER) not in sys.path:
    sys.path.insert(0, str(CONTAINER))

import container_common  # noqa: E402

# Unannotated by design, as every container-side module is, so typed
# here for the checkers; the cast is where basedpyright's strict mode
# wants the unknown to end.
TIMED_OUT: int = container_common.TIMED_OUT
call_with_password = cast(
    Callable[[Sequence[str], str, int], int], container_common.call_with_password
)

# Reads the passphrase as sigul does, then exits; or hangs, as a client
# does on a bridge that accepts and says nothing; or hangs in a child
# that outlives its parent unless the whole group is stopped. The
# grandchild records that it ran, in the file MARKER names.
READER = "import sys; sys.stdin.read(); sys.exit(3)"
HANG = "import sys, time; sys.stdin.read(); time.sleep(60)"
GRANDCHILD = "import os, time; open(os.environ['MARKER'], 'w').close(); time.sleep(60)"
HANG_IN_CHILD = (
    "import subprocess, sys; sys.stdin.read(); "
    f"subprocess.call([sys.executable, '-c', {GRANDCHILD!r}])"
)


class CallWithPasswordTests(unittest.TestCase):
    def password_file(self) -> str:
        path = scratch(self) / "password"
        _ = path.write_bytes(b"secret\0\n")
        return str(path)

    def test_status_passes_through(self) -> None:
        status = call_with_password(
            [sys.executable, "-c", READER], self.password_file(), 0
        )
        self.assertEqual(status, 3)
        status = call_with_password(
            [sys.executable, "-c", READER], self.password_file(), 30
        )
        self.assertEqual(status, 3)

    def test_a_hung_attempt_is_stopped_and_reported(self) -> None:
        started = time.time()
        status = call_with_password(
            [sys.executable, "-c", HANG], self.password_file(), 1
        )
        self.assertEqual(status, TIMED_OUT)
        self.assertLess(time.time() - started, 15)

    def test_the_whole_process_group_is_stopped(self) -> None:
        # The hang is in a grandchild. Were only the child signalled, the
        # grandchild would hold the pipe and this call would not return
        # until it ended of its own accord.
        marker = Path(self.password_file()).with_name("grandchild")
        started = time.time()
        with mock.patch.dict(os.environ, {"MARKER": str(marker)}):
            status = call_with_password(
                [sys.executable, "-c", HANG_IN_CHILD], self.password_file(), 1
            )
        self.assertEqual(status, TIMED_OUT)
        self.assertLess(time.time() - started, 15)
        self.assertTrue(marker.exists(), "the grandchild never started")


if __name__ == "__main__":
    _ = unittest.main()
