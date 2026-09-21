# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/action_common.py."""

from __future__ import annotations

import io
import os
import re
import unittest
from contextlib import redirect_stdout
from unittest import mock

from action_common import SYSTEM_PATH, error, escape_data, minimal_env, shred_file

from tests.helpers import REPOSITORY, scratch


class ShredTests(unittest.TestCase):
    def test_overwrites_before_removing(self) -> None:
        path = scratch(self) / "secret"
        _ = path.write_bytes(b"the secret value" * 5000)
        # A second link to the same inode shows what unlinking alone
        # would have left on disk.
        witness = path.with_name("witness")
        os.link(path, witness)
        shred_file(path)
        self.assertFalse(path.exists())
        self.assertEqual(witness.read_bytes(), bytes(16 * 5000))

    def test_does_not_follow_a_symlink(self) -> None:
        base = scratch(self)
        target = base / "target"
        _ = target.write_text("not ours to overwrite")
        link = base / "link"
        link.symlink_to(target)
        shred_file(link)
        self.assertFalse(link.is_symlink())
        self.assertEqual(target.read_text(), "not ours to overwrite")

    def test_absent_file_is_fine(self) -> None:
        shred_file(scratch(self) / "never-existed")

    def test_read_only_file_is_still_erased(self) -> None:
        path = scratch(self) / "cert8.db"
        _ = path.write_bytes(b"key material")
        witness = path.with_name("witness")
        os.link(path, witness)
        path.chmod(0o400)
        shred_file(path)
        self.assertFalse(path.exists())
        self.assertEqual(witness.read_bytes(), bytes(12))


class WorkflowCommandTests(unittest.TestCase):
    def test_messages_cannot_inject_commands(self) -> None:
        self.assertEqual(escape_data("a%b\r\nc"), "a%25b%0D%0Ac")
        output = io.StringIO()
        with redirect_stdout(output):
            error("bad\n::add-mask::x")
        self.assertEqual(output.getvalue(), "::error::bad%0A::add-mask::x\n")


class EnvironmentTests(unittest.TestCase):
    def test_action_yaml_uses_the_same_system_path(self) -> None:
        # action.yaml sets PATH before starting Python, which then uses
        # SYSTEM_PATH: the two must never drift apart.
        found = re.findall(
            r'^\s*PATH="([^"]*)"$', (REPOSITORY / "action.yaml").read_text(), re.M
        )
        self.assertEqual(found, [SYSTEM_PATH, SYSTEM_PATH])

    def test_minimal_env_carries_no_secret(self) -> None:
        with mock.patch.dict(os.environ, {"SIGUL_PASS": "secret"}):
            env = minimal_env({"HOME": "/h"})
        self.assertNotIn("SIGUL_PASS", env)
        self.assertEqual(env["HOME"], "/h")
        self.assertEqual(env["PATH"], SYSTEM_PATH)


if __name__ == "__main__":
    _ = unittest.main()
