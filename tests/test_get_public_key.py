# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run scripts/container/get_public_key.py against tests/mock-sigul.

The script is a real subprocess, as the container runs it, and the
mock is the one the end-to-end image puts on PATH. Nothing contacts a
server or starts a container.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

from tests.helpers import REPOSITORY, scratch
from tests.test_bridge_guard import EXPECTED, OTHER_BRIDGE, BridgeFixture

SCRIPT = REPOSITORY / "scripts" / "container" / "get_public_key.py"
PASSPHRASE = "sigul-test-passphrase"
PUBLIC_KEY = (
    b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmock public key\n"
    + b"-----END PGP PUBLIC KEY BLOCK-----\n"
)


class GetPublicKeyFixture:
    def __init__(self, case: unittest.TestCase) -> None:
        self.case: unittest.TestCase = case
        self.root: Path = scratch(case)
        self.bin: Path = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "sigul").symlink_to(REPOSITORY / "tests" / "mock-sigul")
        self.state: Path = self.root / "state"
        self.public_key: Path = self.root / "mock-public-key.asc"
        _ = self.public_key.write_bytes(PUBLIC_KEY)
        self.password: Path = self.root / "password"
        _ = self.password.write_bytes(PASSPHRASE.encode() + b"\0\n")
        self.output: Path = self.root / "creds" / "public-key"
        self.output.parent.mkdir()

    def run(self, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin",
            "HOME": str(self.root),
            "SIGUL_KEY": "test-key",
            "SIGUL_PASSWORD": str(self.password),
            "PUBLIC_KEY_FILE": str(self.output),
            "MAX_RETRIES": "1",
            "RETRY_DELAY": "0",
            "ATTEMPT_TIMEOUT": "0",
            "MOCK_PASSPHRASE": PASSPHRASE,
            "MOCK_PUBLIC_KEY": str(self.public_key),
            "MOCK_STATE": str(self.state),
            **extra,
        }
        done = subprocess.run(
            [sys.executable, "-B", "-E", "-S", str(SCRIPT)],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        case = self.case
        case.addCleanup(case.assertNotIn, "Traceback", done.stdout + done.stderr)
        return done


class GetPublicKeyTests(unittest.TestCase):
    def test_writes_the_public_key_privately(self) -> None:
        fixture = GetPublicKeyFixture(self)
        done = fixture.run()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(fixture.output.read_bytes(), PUBLIC_KEY)
        self.assertEqual(fixture.output.stat().st_mode & 0o777, 0o600)
        # The key goes to the file, never to the log.
        self.assertNotIn("mock public key", done.stdout + done.stderr)

    def test_a_wrong_passphrase_fails_and_leaves_nothing(self) -> None:
        fixture = GetPublicKeyFixture(self)
        _ = fixture.password.write_bytes(b"not-the-passphrase\0\n")
        done = fixture.run(MAX_RETRIES="2")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("after 2 attempt(s)", done.stderr)
        self.assertIn("retrying in 0s", done.stderr)
        self.assertFalse(fixture.output.exists())
        self.assertNotIn("not-the-passphrase", done.stdout + done.stderr)

    def test_a_transient_failure_is_retried(self) -> None:
        fixture = GetPublicKeyFixture(self)
        done = fixture.run(MAX_RETRIES="2", MOCK_FAIL_GET_PUBLIC_KEY_ONCE="1")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("(attempt 1/2), retrying in 0s", done.stderr)
        self.assertEqual(fixture.output.read_bytes(), PUBLIC_KEY)

    def test_retries_are_bounded(self) -> None:
        fixture = GetPublicKeyFixture(self)
        done = fixture.run(MAX_RETRIES="1", MOCK_FAIL_GET_PUBLIC_KEY_ONCE="1")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("after 1 attempt(s)", done.stderr)
        self.assertFalse(fixture.output.exists())

    def test_a_hung_attempt_is_stopped_and_retried(self) -> None:
        fixture = GetPublicKeyFixture(self)
        done = fixture.run(
            MAX_RETRIES="2", ATTEMPT_TIMEOUT="1", MOCK_HANG_GET_PUBLIC_KEY_ONCE="1"
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("did not finish within 1s", done.stderr)
        self.assertEqual(fixture.output.read_bytes(), PUBLIC_KEY)

    def test_an_empty_reply_is_a_failure(self) -> None:
        fixture = GetPublicKeyFixture(self)
        # The mock refuses to print an empty key, so stand in a client
        # that exits zero and prints nothing.
        (fixture.bin / "sigul").unlink()
        (fixture.bin / "sigul").symlink_to("/bin/true")
        done = fixture.run(MAX_RETRIES="2")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("exited zero but returned no public key", done.stderr)
        self.assertFalse(fixture.output.exists())

    def test_a_stale_reply_is_replaced(self) -> None:
        fixture = GetPublicKeyFixture(self)
        _ = fixture.output.write_bytes(b"stale")
        done = fixture.run()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(fixture.output.read_bytes(), PUBLIC_KEY)

    def test_required_environment(self) -> None:
        for name in ("SIGUL_KEY", "SIGUL_PASSWORD", "PUBLIC_KEY_FILE"):
            with self.subTest(name=name):
                fixture = GetPublicKeyFixture(self)
                done = fixture.run(**{name: ""})
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn(name + " is required", done.stderr)

    def test_an_oversized_reply_fails_without_a_retry_or_a_trace(self) -> None:
        # A reply over the cap is not transient: the next attempt would
        # stream the same key. It fails at once and leaves no file.
        fixture = GetPublicKeyFixture(self)
        done = fixture.run(MAX_RETRIES="3", PUBLIC_KEY_LIMIT="16")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("exceeds 16 bytes", done.stderr)
        self.assertNotIn("retrying", done.stderr)
        self.assertFalse(fixture.output.exists())

    def test_the_cap_must_be_a_positive_integer(self) -> None:
        for raw in ("0", "lots"):
            with self.subTest(raw=raw):
                fixture = GetPublicKeyFixture(self)
                done = fixture.run(PUBLIC_KEY_LIMIT=raw)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn("PUBLIC_KEY_LIMIT", done.stderr)
                self.assertFalse(fixture.output.exists())


class ExpectedBridgeTests(unittest.TestCase):
    def test_refuses_an_unexpected_bridge_before_running_sigul(self) -> None:
        fixture = BridgeFixture(self)
        fixture.configure(host=OTHER_BRIDGE)
        output = fixture.root / "public-key"
        done = fixture.run("get-public-key", EXPECTED, PUBLIC_KEY_FILE=str(output))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("expected-bridge", done.stderr)
        self.assertEqual(fixture.events("signing-command"), [])
        self.assertEqual(fixture.events("connect"), [])
        self.assertFalse(output.exists())
        self.assertNotIn(OTHER_BRIDGE, done.stdout + done.stderr)


if __name__ == "__main__":
    _ = unittest.main()
