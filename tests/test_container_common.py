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
# Prints its argument as the reply, then exits 0; or keeps printing,
# 64 KiB at a time, for as long as anything reads, as a reply with no
# end would.
PRINTER = "import sys; sys.stdin.read(); sys.stdout.write(sys.argv[1])"
FLOOD = (
    "import sys; sys.stdin.read()\n"
    + "while True:\n    sys.stdout.write('x' * 65536); sys.stdout.flush()"
)
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
        # Reaped since the probe: ENOENT if gone before the open, ESRCH
        # if gone after it. Any other error is not evidence it stopped.
        try:
            text = status.read_text()
        except (FileNotFoundError, ProcessLookupError):
            return False
        for line in text.splitlines():
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


# Never signalled: os.kill is mocked wherever it is used.
SYNTHETIC_PID = 4194304


class IsRunningTests(unittest.TestCase):
    """The helper above, driven through mocks rather than real processes.

    A race between the procfs existence check and the read cannot be
    hit on demand with a real child, so each state is injected.
    """

    def check(
        self,
        exists: bool,
        read: str | BaseException = "",
        ps: str = "",
        kill: BaseException | None = None,
    ) -> bool:
        with (
            mock.patch.object(os, "kill", side_effect=kill),
            mock.patch.object(Path, "exists", return_value=exists),
            mock.patch.object(Path, "read_text", side_effect=[read]),
            mock.patch.object(
                subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, stdout=ps),
            ),
        ):
            return is_running(SYNTHETIC_PID)

    def test_absent_at_the_signal_probe(self) -> None:
        self.assertFalse(self.check(True, kill=ProcessLookupError()))

    def test_procfs_states(self) -> None:
        self.assertTrue(self.check(True, "Name:\tx\nState:\tR (running)\n"))
        self.assertTrue(self.check(True, "Name:\tx\nState:\tS (sleeping)\n"))
        self.assertFalse(self.check(True, "Name:\tx\nState:\tZ (zombie)\n"))

    def test_reaped_between_the_check_and_the_read(self) -> None:
        reaped = FileNotFoundError(2, "synthetic process reaped")
        self.assertFalse(self.check(True, reaped))

    def test_reaped_while_the_status_is_open(self) -> None:
        # Linux reports ESRCH, not ENOENT, for a status file opened
        # before its process went away.
        self.assertFalse(self.check(True, ProcessLookupError(3, "reaped")))

    def test_other_read_failures_are_not_termination(self) -> None:
        with self.assertRaises(PermissionError):
            _ = self.check(True, PermissionError(13, "denied"))
        with self.assertRaises(OSError):
            _ = self.check(True, OSError(5, "I/O error"))

    def test_fallback_without_procfs(self) -> None:
        self.assertTrue(self.check(False, ps="S\n"))
        self.assertFalse(self.check(False, ps="Z\n"))
        self.assertFalse(self.check(False, ps=""))


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


class CappedOutputTests(unittest.TestCase):
    """call_with_password with stdout to a file, capped at a byte count."""

    @staticmethod
    def too_large() -> int:
        """The status for an over-cap reply, looked up when a test runs."""
        return cast(int, vars(container_common)["TOO_LARGE"])

    def call(self, script: str, *args: str, limit: int = 1024) -> tuple[int, bytes]:
        root = scratch(self)
        password = root / "password"
        _ = password.write_bytes(b"secret\0\n")
        output = root / "reply"
        capped = cast(
            Callable[..., int],
            container_common.call_with_password,
        )
        with output.open("wb") as handle:
            status = capped(
                [sys.executable, "-c", script, *args],
                str(password),
                30,
                stdout=handle,
                limit=limit,
            )
        return status, output.read_bytes()

    def test_a_reply_within_the_cap_passes_through(self) -> None:
        status, written = self.call(PRINTER, "a" * 1024)
        self.assertEqual(status, 0)
        self.assertEqual(written, b"a" * 1024)

    def test_a_reply_over_the_cap_is_stopped_while_it_streams(self) -> None:
        # The client never ends of its own accord, so only the cap,
        # enforced while the reply arrives, can stop it in time.
        started = time.time()
        status, written = self.call(FLOOD, limit=4096)
        self.assertEqual(status, self.too_large())
        self.assertLessEqual(len(written), 4096)
        self.assertLess(time.time() - started, 15)

    def test_one_byte_over_the_cap_is_refused(self) -> None:
        status, _written = self.call(PRINTER, "a" * 1025)
        self.assertEqual(status, self.too_large())


if __name__ == "__main__":
    _ = unittest.main()
