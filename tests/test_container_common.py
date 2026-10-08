# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/container/container_common.py's process handling.

Those scripts are held to Python 2.7 as well as 3, and import nothing
from the runner side, so they are imported here directly. The
end-to-end job runs them under each image's own Python.
"""

from __future__ import annotations

import os
import subprocess
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
stop_process_group = cast(
    Callable[[subprocess.Popen[bytes]], None], container_common.stop_process_group
)

# Reads the passphrase as sigul does, then exits; or hangs, as a client
# does on a bridge that accepts and says nothing; or hangs in a child
# that outlives its parent unless the whole group is stopped. The
# grandchild records that it ran, in the file MARKER names; the
# stubborn one records its PID there and ignores SIGTERM, so only a
# kill of the whole group ends it.
READER = "import sys; sys.stdin.read(); sys.exit(3)"
HANG = "import sys, time; sys.stdin.read(); time.sleep(60)"
GRANDCHILD = "import os, time; open(os.environ['MARKER'], 'w').close(); time.sleep(60)"
HANG_IN_CHILD = (
    "import subprocess, sys; sys.stdin.read(); "
    f"subprocess.call([sys.executable, '-c', {GRANDCHILD!r}])"
)
STUBBORN_GRANDCHILD = (
    "import os, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
    "open(os.environ['MARKER'], 'w').write(str(os.getpid())); time.sleep(60)"
)
# The child itself takes SIGTERM's default action and dies at once,
# leaving the stubborn grandchild behind in the group.
STUBBORN_IN_CHILD = (
    "import subprocess, sys; sys.stdin.read(); "
    f"subprocess.call([sys.executable, '-c', {STUBBORN_GRANDCHILD!r}])"
)


def is_running(pid: int) -> bool:
    """Whether a process is alive and not a zombie.

    A killed orphan lingers as a zombie until whoever inherited it reaps
    it, which the harness around a test may not do promptly (inside the
    container, the script itself is PID 1 and reaps its own); kill(pid,
    0) succeeds on a zombie, so the state is read as well.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        for line in status.read_text().splitlines():
            if line.startswith("State:"):
                return not line.split()[1].startswith("Z")
        return False
    done = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    state = done.stdout.strip()
    return bool(state) and not state.startswith("Z")


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

    def test_a_group_already_gone_is_not_an_error(self) -> None:
        # The process can end in the instant between the deadline passing
        # and the stop: by then its group may have no members, and
        # signalling it must be the outcome wanted, not a traceback that
        # abandons the retry.
        process = subprocess.Popen([sys.executable, "-c", "pass"], preexec_fn=os.setsid)
        self.assertEqual(process.wait(), 0)
        stop_process_group(process)
        self.assertEqual(process.returncode, 0)

    def test_a_descendant_that_ignores_sigterm_is_still_stopped(self) -> None:
        # The child dies on SIGTERM at once; its grandchild ignores it.
        # The stop must not return while the grandchild lives, or the
        # retry would run beside it; after the grace period it is killed.
        marker = Path(self.password_file()).with_name("stubborn")
        started = time.time()
        with (
            mock.patch.dict(os.environ, {"MARKER": str(marker)}),
            mock.patch.object(container_common, "GRACE_SECONDS", 1),
        ):
            status = call_with_password(
                [sys.executable, "-c", STUBBORN_IN_CHILD], self.password_file(), 1
            )
        self.assertEqual(status, TIMED_OUT)
        self.assertLess(time.time() - started, 15)
        self.assertTrue(marker.exists(), "the grandchild never started")
        grandchild = int(marker.read_text())
        self.assertFalse(is_running(grandchild), "the grandchild outlived the stop")


if __name__ == "__main__":
    _ = unittest.main()
