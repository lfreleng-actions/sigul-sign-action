# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Cancellation and cleanup tests using only private synthetic material."""

from __future__ import annotations

import io
import os
import signal
import subprocess
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock

from action_common import ActionError, shred_file
from action_inputs import Plan, build_plan
from client_container import PulledImage, run_container
from prepare_credentials import PreparedCredentials
from signing import clear_stale_signatures, sign
from sigul_action import Cancelled, on_signal

from tests.helpers import PINS_DIR, base_env, scratch


class SigningFixture:
    """Keep every filesystem write and external operation inside a fixture."""

    def __init__(self, case: unittest.TestCase) -> None:
        self.base: Path = scratch(case)
        self.work: Path = self.base / "work"
        self.gnupg: Path = self.base / "gnupg"
        self.work.mkdir()
        self.gnupg.mkdir()
        _ = (self.base / "a.txt").write_text("payload")
        self.plan: Plan = build_plan(base_env(self.base, CONTAINER="modern"), PINS_DIR)
        self.creds: Path = self.work / "creds"

    def prepare(self, *_args: object) -> PreparedCredentials:
        self.creds.mkdir()
        _ = (self.creds / "password").write_bytes(b"synthetic-passphrase\0\n")
        _ = (self.creds / "key.db").write_bytes(b"synthetic-key")
        return PreparedCredentials(
            self.creds / "client.conf", "/sigul-creds/pki", "/n", False
        )

    def isolate(self, stack: ExitStack) -> None:
        patches = {
            "private_directory": mock.Mock(side_effect=[self.work, self.gnupg]),
            "daemon_security_options": mock.Mock(return_value=""),
            "pull_image": mock.Mock(
                return_value=PulledImage("image:1", "image:1", "root", "linux/amd64")
            ),
            "prepare": mock.Mock(side_effect=self.prepare),
            "kill_gpg_agent": mock.Mock(),
            "sign_data": mock.Mock(),
            "remove_container": mock.Mock(),
        }
        for name, replacement in patches.items():
            _ = stack.enter_context(mock.patch("signing." + name, replacement))
        _ = stack.enter_context(redirect_stdout(io.StringIO()))

    def run(self) -> None:
        sign(
            self.plan,
            {
                "SIGUL_CONF": "synthetic",
                "SIGUL_PASS": "synthetic",
                "SIGUL_PKI": "synthetic",
                "GH_KEY": "",
            },
        )


class CleanupSignalTests(unittest.TestCase):
    def test_first_signal_during_final_cleanup_does_not_abandon_secrets(self) -> None:
        fixture = SigningFixture(self)
        fired = False

        def interrupt(path: Path) -> None:
            nonlocal fired
            if not fired and path.name == "password":
                fired = True
                os.kill(os.getpid(), signal.SIGTERM)
            shred_file(path)

        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous = signal.signal(signum, on_signal)
            self.addCleanup(signal.signal, signum, previous)
        with ExitStack() as stack:
            fixture.isolate(stack)
            _ = stack.enter_context(
                mock.patch("signing.shred_file", side_effect=interrupt)
            )
            with self.assertRaises(Cancelled):
                fixture.run()
        self.assertTrue(fired)
        self.assertFalse(fixture.creds.exists())
        self.assertFalse(fixture.work.exists())

    def test_one_cleanup_failure_does_not_abandon_other_secrets(self) -> None:
        fixture = SigningFixture(self)
        visited: list[Path] = []

        def erase(path: Path) -> None:
            visited.append(path)
            if path == fixture.creds or path == fixture.work:
                raise OSError("synthetic cleanup failure")

        with ExitStack() as stack:
            fixture.isolate(stack)
            _ = stack.enter_context(mock.patch("signing.destroy", side_effect=erase))
            try:
                fixture.run()
            except (ActionError, OSError):
                pass
        self.assertIn(fixture.gnupg, visited)
        self.assertGreater(visited.count(fixture.gnupg), 1)


class UnreapableCLI:
    """Model a process that remains unreapable even after kill."""

    def __init__(self) -> None:
        self.waits: list[float | None] = []
        self.pid: int = 1_000_000_000

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        self.waits.append(timeout)
        raise subprocess.TimeoutExpired("synthetic-cli", timeout or 0)


class ProcessReapingTests(unittest.TestCase):
    def test_unreapable_cli_never_causes_an_unbounded_wait(self) -> None:
        process = UnreapableCLI()
        with (
            mock.patch("client_container.subprocess.Popen", return_value=process),
            mock.patch("client_container.remove_container"),
            mock.patch("process_control.os.killpg") as kill_group,
            mock.patch("process_control.time.monotonic", side_effect=[0.0, 1.0]),
            redirect_stdout(io.StringIO()),
        ):
            try:
                _ = run_container(["synthetic-cli"], "not-a-container", 1)
            except (ActionError, subprocess.TimeoutExpired):
                pass
        kill_group.assert_any_call(process.pid, signal.SIGKILL)
        self.assertNotIn(None, process.waits)


class StaleCleanupTests(unittest.TestCase):
    def test_failed_unlink_does_not_skip_later_stale_signatures(self) -> None:
        workspace = scratch(self)
        for name in ("a.txt", "b.txt", "c.txt"):
            _ = (workspace / name).write_text("payload")
            _ = (workspace / (name + ".asc")).write_text("stale")
        plan = build_plan(
            base_env(workspace, CONTAINER="modern", SIGN_OBJECT="*.txt"), PINS_DIR
        )
        unlink = os.remove

        def remove(path: str) -> None:
            if Path(path).name == "b.txt.asc":
                raise PermissionError("synthetic permission failure")
            unlink(path)

        with mock.patch("signing.os.remove", side_effect=remove):
            with self.assertRaises((ActionError, OSError)):
                clear_stale_signatures(plan)
        self.assertFalse((workspace / "a.txt.asc").exists())
        self.assertTrue((workspace / "b.txt.asc").exists())
        self.assertFalse((workspace / "c.txt.asc").exists())


if __name__ == "__main__":
    _ = unittest.main()
