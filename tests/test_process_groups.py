# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Real descendant lifetimes at the captured and streaming command boundaries."""

from __future__ import annotations

import fcntl
import io
import os
import signal
import subprocess
import sys
import time
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from subprocess import Popen
from unittest import mock

from action_common import ActionError, minimal_env
from client_container import run_container
from process_control import capture_bytes
from termination import Cancelled

from tests.helpers import scratch

# A lock witnesses a live helper without confusing zombies with running code.
# Neither process can live indefinitely if the test's cleanup is interrupted.
TREE = """
import fcntl
import os
import signal
import sys
import time
from pathlib import Path

lock, ready = (Path(value) for value in sys.argv[1:3])
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    with lock.open('wb') as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        temporary = ready.with_suffix('.tmp')
        temporary.write_text(str(os.getpid()) + ' ' + str(os.getpgrp()))
        temporary.replace(ready)
        time.sleep(30)
    os._exit(0)
if sys.argv[3] == 'exit':
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    os._exit(0)
time.sleep(30)
"""


class ProcessTree:
    """Start real processes, injecting interruption after the helper is ready."""

    def __init__(self, case: unittest.TestCase) -> None:
        root = scratch(case)
        self.lock: Path = root / "helper.lock"
        self.ready: Path = root / "ready"
        self.processes: list[Popen[bytes]] = []
        self.child: int | None = None
        self.group: int | None = None
        case.addCleanup(self.cleanup)

    def await_helper(self) -> None:
        deadline = time.monotonic() + 5
        while not self.ready.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("fixture helper did not start")
            time.sleep(0.01)
        self.child, self.group = (
            int(value) for value in self.ready.read_text().split()
        )

    def released(self) -> bool:
        with self.lock.open("a+b") as held:
            try:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
        return True

    def helper_stopped(self) -> bool:
        deadline = time.monotonic() + 0.5
        while not self.released():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def cleanup(self) -> None:
        if self.child is None and self.ready.exists():
            self.await_helper()
        if self.child is not None and not self.released():
            # The still-held private lock identifies our surviving fixture helper.
            try:
                os.kill(self.child, signal.SIGKILL)
            except ProcessLookupError:
                self.child = None
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            _ = process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def command(self, parent_exits: bool) -> list[str]:
        return [
            sys.executable,
            "-I",
            "-B",
            "-c",
            TREE,
            str(self.lock),
            str(self.ready),
            "exit" if parent_exits else "stay",
        ]

    def exercise(self, *, streaming: bool, cancel: bool, parent_exits: bool) -> None:
        with ExitStack() as stack:

            def launch(
                argv: list[str],
                *,
                env: dict[str, str],
                cwd: Path | None = None,
                stdout: int | None = None,
                stderr: int | None = None,
                start_new_session: bool = False,
            ) -> Popen[bytes]:
                process = Popen(
                    argv,
                    env=env,
                    cwd=cwd,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=start_new_session,
                )
                self.processes.append(process)
                communicate = process.communicate
                wait = process.wait

                def captured(timeout: float | None = None) -> tuple[bytes, bytes]:
                    self.await_helper()
                    if parent_exits:
                        _ = wait(timeout=5)
                    if cancel:
                        raise Cancelled("fixture cancellation")
                    return communicate(timeout=timeout)

                def streamed(timeout: float | None = None) -> int:
                    self.await_helper()
                    if parent_exits:
                        _ = wait(timeout=5)
                    if cancel:
                        raise Cancelled("fixture cancellation")
                    return wait(timeout=timeout)

                method = "wait" if streaming else "communicate"
                _ = stack.enter_context(
                    mock.patch.object(
                        process, method, side_effect=streamed if streaming else captured
                    )
                )
                return process

            _ = stack.enter_context(mock.patch("subprocess.Popen", side_effect=launch))
            _ = stack.enter_context(redirect_stdout(io.StringIO()))
            if streaming:
                _ = run_container(self.command(parent_exits), "fixture-not-docker", 1)
            else:
                _ = capture_bytes(
                    self.command(parent_exits), env=minimal_env(), timeout=0.05
                )


@unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process groups")
class ProcessGroupTests(unittest.TestCase):
    def check_tree(
        self,
        *,
        streaming: bool = False,
        cancel: bool = False,
        parent_exits: bool = False,
    ) -> None:
        tree = ProcessTree(self)
        expected = (
            Cancelled
            if cancel
            else (ActionError if streaming else subprocess.TimeoutExpired)
        )
        with self.assertRaises(expected):
            tree.exercise(streaming=streaming, cancel=cancel, parent_exits=parent_exits)
        self.assertTrue(tree.helper_stopped(), "a helper survived command cancellation")
        self.assertEqual(tree.group, tree.processes[0].pid)
        self.assertNotEqual(tree.group, os.getpgrp())

    @unittest.expectedFailure
    def test_capture_timeout_stops_a_real_helper(self) -> None:
        self.check_tree()

    @unittest.expectedFailure
    def test_capture_cancellation_stops_a_real_helper(self) -> None:
        self.check_tree(cancel=True)

    @unittest.expectedFailure
    def test_capture_cancellation_reaches_helpers_after_parent_exit(self) -> None:
        self.check_tree(cancel=True, parent_exits=True)

    @unittest.expectedFailure
    def test_stream_timeout_stops_a_real_helper(self) -> None:
        self.check_tree(streaming=True)

    @unittest.expectedFailure
    def test_stream_cancellation_stops_a_real_helper(self) -> None:
        self.check_tree(streaming=True, cancel=True)

    @unittest.expectedFailure
    def test_stream_cancellation_reaches_helpers_after_parent_exit(self) -> None:
        self.check_tree(streaming=True, cancel=True, parent_exits=True)


if __name__ == "__main__":
    _ = unittest.main()
