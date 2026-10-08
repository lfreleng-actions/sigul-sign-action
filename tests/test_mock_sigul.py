# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Check mock-sigul's complete stdin framing without signing or a container."""

from __future__ import annotations

import subprocess
import unittest

from tests.helpers import REPOSITORY, scratch

PASSPHRASE = b"sigul-test-passphrase"


def mock_precheck() -> str:
    """Stop before global retry state or signing side effects."""
    source = (REPOSITORY / "tests" / "mock-sigul").read_text()
    precheck, boundary, _ = source.partition('\nstate="/tmp/mock-sigul-state"')
    if not boundary:
        raise ValueError("Cannot isolate mock-sigul's stdin precheck")
    return precheck


# A changed boundary fails collection, outside any expectedFailure marker.
PRECHECK = mock_precheck()


class MockPassphraseTests(unittest.TestCase):
    def precheck(self, payload: bytes) -> subprocess.CompletedProcess[bytes]:
        root = scratch(self)
        return subprocess.run(
            [
                "/bin/sh",
                "-c",
                PRECHECK,
                "mock-sigul",
                "--batch",
                "sign-data",
                "-a",
                "-o",
                "payload.asc",
                "--",
                "test-key",
                "payload",
            ],
            input=payload,
            cwd=root,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(root),
                "TMPDIR": str(root),
                "MOCK_PASSPHRASE": PASSPHRASE.decode(),
            },
            capture_output=True,
            timeout=5,
            check=False,
        )

    def assert_bad_framing(self, payload: bytes) -> None:
        done = self.precheck(payload)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)

    def test_fixture_scripts_use_the_same_synthetic_passphrase(self) -> None:
        scripts = REPOSITORY / "tests"
        self.assertIn(
            f'passphrase="{PASSPHRASE.decode()}"',
            (scripts / "make-test-credentials.sh").read_text(),
        )
        self.assertIn(
            f"ENV MOCK_PASSPHRASE={PASSPHRASE.decode()} ",
            (scripts / "build-mock-image.sh").read_text(),
        )

    def test_exact_password_file_framing_is_accepted(self) -> None:
        done = self.precheck(PASSPHRASE + b"\0\n")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_wrong_passphrase_is_rejected(self) -> None:
        self.assert_bad_framing(b"wrong-passphrase\0\n")

    def test_empty_input_is_rejected(self) -> None:
        self.assert_bad_framing(b"")

    def test_missing_terminator_is_rejected(self) -> None:
        self.assert_bad_framing(PASSPHRASE)

    def test_nul_without_final_newline_is_rejected(self) -> None:
        self.assert_bad_framing(PASSPHRASE + b"\0")

    def test_newline_without_nul_is_rejected(self) -> None:
        self.assert_bad_framing(PASSPHRASE + b"\n")

    def test_multiple_nul_terminators_are_rejected(self) -> None:
        self.assert_bad_framing(PASSPHRASE + b"\0\0\n")

    def test_bytes_between_nul_and_newline_are_rejected(self) -> None:
        self.assert_bad_framing(PASSPHRASE + b"\0trailing\n")

    def test_bytes_after_complete_frame_are_rejected(self) -> None:
        self.assert_bad_framing(PASSPHRASE + b"\0\ntrailing")

    def test_additional_line_before_nul_is_rejected(self) -> None:
        self.assert_bad_framing(PASSPHRASE + b"\nsecond line\0\n")

    def test_additional_newline_after_complete_frame_is_rejected(self) -> None:
        self.assert_bad_framing(PASSPHRASE + b"\0\n\n")


if __name__ == "__main__":
    _ = unittest.main()
