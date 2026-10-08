# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Exercise cancellation-safe capture without inducing kernel I/O failures."""

from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import unittest
from unittest import mock

from action_common import minimal_env
from process_control import capture_bytes, capture_text, kill_and_poll
from termination import Cancelled, defer_termination


class UnreapableProcess:
    """A command whose streams time out and whose exit cannot be awaited."""

    def __init__(self, failure: BaseException) -> None:
        self.failure: BaseException = failure
        self.stdout: io.BytesIO = io.BytesIO()
        self.stderr: io.BytesIO = io.BytesIO()
        self.returncode: int | None = None
        self.pid: int = 1_000_000_000
        self.polled: bool = False

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        if timeout is None:
            raise AssertionError("this fixture requires a bounded capture")
        raise self.failure

    def poll(self) -> int | None:
        self.polled = True
        return None

    def wait(self, timeout: float | None = None) -> int:
        raise AssertionError(f"unexpected post-kill wait with timeout {timeout}")


class CaptureTests(unittest.TestCase):
    def test_raw_payloads_are_not_newline_normalized(self) -> None:
        done = capture_bytes(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'a\\r\\nb\\n')",
            ],
            env=minimal_env(),
            timeout=5,
        )
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, b"a\r\nb\n")

    def test_text_capture_preserves_exit_status_and_decodes_errors(self) -> None:
        done = capture_text(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('fixture'); sys.exit(7)",
            ],
            env=minimal_env(),
            timeout=5,
        )
        self.assertEqual(done.returncode, 7)
        self.assertEqual(done.stderr, "fixture")

    def test_timeout_kills_without_waiting_for_reaping(self) -> None:
        process = UnreapableProcess(subprocess.TimeoutExpired("fixture", 1))
        with (
            mock.patch("process_control.subprocess.Popen", return_value=process),
            mock.patch("process_control.os.killpg") as kill_group,
            mock.patch("process_control.time.monotonic", side_effect=[0.0, 1.0]),
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                _ = capture_bytes(["fixture"], env={}, timeout=1)
        kill_group.assert_has_calls(
            [mock.call(process.pid, signal.SIGKILL), mock.call(process.pid, 0)]
        )
        self.assertTrue(process.polled)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_cancellation_kills_without_waiting_for_reaping(self) -> None:
        process = UnreapableProcess(Cancelled("synthetic cancellation"))
        with (
            mock.patch("process_control.subprocess.Popen", return_value=process),
            mock.patch("process_control.os.killpg") as kill_group,
            mock.patch("process_control.time.monotonic", side_effect=[0.0, 1.0]),
        ):
            with self.assertRaisesRegex(Cancelled, "synthetic cancellation"):
                _ = capture_bytes(["fixture"], env={}, timeout=1)
        kill_group.assert_any_call(process.pid, signal.SIGKILL)
        self.assertTrue(process.polled)

    def test_an_already_gone_group_is_polled_without_waiting(self) -> None:
        process = UnreapableProcess(Cancelled("unused"))
        with (
            mock.patch("process_control.subprocess.Popen", return_value=process),
            mock.patch("process_control.os.killpg", side_effect=ProcessLookupError),
        ):
            with self.assertRaises(Cancelled):
                _ = capture_bytes(["fixture"], env={}, timeout=1)
        self.assertTrue(process.polled)

    def test_denied_exit_probe_is_bounded_and_preserves_cancellation(self) -> None:
        process = UnreapableProcess(Cancelled("synthetic cancellation"))
        with (
            mock.patch("process_control.subprocess.Popen", return_value=process),
            mock.patch(
                "process_control.os.killpg", side_effect=[None, PermissionError]
            ),
            mock.patch("process_control.time.monotonic", side_effect=[0.0, 1.0]),
        ):
            with self.assertRaisesRegex(Cancelled, "synthetic cancellation"):
                _ = capture_bytes(["fixture"], env={}, timeout=1)
        self.assertTrue(process.polled)

    def test_group_termination_never_targets_the_action_itself(self) -> None:
        with mock.patch("process_control.os.killpg") as kill_group:
            with self.assertRaisesRegex(ValueError, "own process group"):
                process = mock.Mock(spec=subprocess.Popen)
                process.pid = os.getpgrp()
                kill_and_poll(process)
        kill_group.assert_not_called()

    def test_missing_tool_is_not_misreported_as_a_command_failure(self) -> None:
        with self.assertRaises(FileNotFoundError):
            _ = capture_bytes(["/nonexistent/sigul-test-tool"], env={}, timeout=1)


class DeferredTerminationTests(unittest.TestCase):
    def test_cleanup_signal_preserves_the_error_already_unwinding(self) -> None:
        cleaned = False
        with self.assertRaisesRegex(ValueError, "original failure"):
            try:
                raise ValueError("original failure")
            finally:
                with defer_termination():
                    handler = signal.getsignal(signal.SIGTERM)
                    self.assertTrue(callable(handler))
                    if callable(handler):
                        handler(signal.SIGTERM, None)
                    cleaned = True
        self.assertTrue(cleaned)


if __name__ == "__main__":
    _ = unittest.main()
