# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Exercise cancellation-safe capture without inducing kernel I/O failures."""

from __future__ import annotations

import io
import signal
import subprocess
import sys
import unittest
from unittest import mock

from action_common import minimal_env
from process_control import capture_bytes, capture_text
from termination import Cancelled, defer_termination


class UnreapableProcess:
    """A command whose streams time out and whose exit cannot be awaited."""

    def __init__(self, failure: BaseException) -> None:
        self.failure: BaseException = failure
        self.stdout: io.BytesIO = io.BytesIO()
        self.stderr: io.BytesIO = io.BytesIO()
        self.returncode: int | None = None
        self.killed: bool = False
        self.polled: bool = False

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        if timeout is None:
            raise AssertionError("this fixture requires a bounded capture")
        raise self.failure

    def kill(self) -> None:
        self.killed = True

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
        with mock.patch("process_control.subprocess.Popen", return_value=process):
            with self.assertRaises(subprocess.TimeoutExpired):
                _ = capture_bytes(["fixture"], env={}, timeout=1)
        self.assertTrue(process.killed)
        self.assertTrue(process.polled)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_cancellation_kills_without_waiting_for_reaping(self) -> None:
        process = UnreapableProcess(Cancelled("synthetic cancellation"))
        with mock.patch("process_control.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(Cancelled, "synthetic cancellation"):
                _ = capture_bytes(["fixture"], env={}, timeout=1)
        self.assertTrue(process.killed)
        self.assertTrue(process.polled)

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
