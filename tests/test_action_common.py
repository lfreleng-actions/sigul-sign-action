# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/action_common.py."""

from __future__ import annotations

import io
import os
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from action_common import (
    SYSTEM_PATH,
    ActionError,
    check_trusted_location,
    error,
    escape_data,
    is_untrusted_directory,
    minimal_env,
    shred_file,
)

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

    def test_action_yaml_refuses_a_planted_interpreter(self) -> None:
        # Both steps must check the interpreter's directory before
        # running it, with builtins only, and skip the test as root.
        text = (REPOSITORY / "action.yaml").read_text()
        self.assertEqual(text.count('python3="$(type -P python3)"'), 2)
        self.assertEqual(
            text.count('if (( EUID != 0 )) && [[ -w "${python3%/*}" ]]; then'), 2
        )

    def test_minimal_env_carries_no_secret(self) -> None:
        with mock.patch.dict(os.environ, {"SIGUL_PASS": "secret"}):
            env = minimal_env({"HOME": "/h"})
        self.assertNotIn("SIGUL_PASS", env)
        self.assertEqual(env["HOME"], "/h")
        self.assertEqual(env["PATH"], SYSTEM_PATH)


class TrustedLocationTests(unittest.TestCase):
    """Tools are refused where an earlier step could have planted them."""

    def make_tool(self, directory: Path, mode: int) -> Path:
        directory.mkdir()
        tool = directory / "gpg"
        _ = tool.write_text("#!/bin/sh\n")
        directory.chmod(mode)
        self.addCleanup(directory.chmod, 0o755)
        return tool

    def test_world_writable_directory_is_refused_by_everyone(self) -> None:
        # Whatever user runs the tests, root included: the mode bits
        # alone decide. This is /usr/local/bin on a GitHub-hosted runner.
        tool = self.make_tool(scratch(self) / "bin", 0o777)
        self.assertTrue(is_untrusted_directory(str(tool.parent)))
        with self.assertRaises(ActionError) as caught:
            check_trusted_location(str(tool))
        self.assertIn("an earlier step could have planted it", str(caught.exception))

    def test_directory_this_user_cannot_write_is_trusted(self) -> None:
        # Owned by this user but without its write bit, as /usr/bin is
        # root's without anyone else's.
        tool = self.make_tool(scratch(self) / "bin", 0o555)
        self.assertFalse(is_untrusted_directory(str(tool.parent)))
        check_trusted_location(str(tool))

    @unittest.skipIf(os.geteuid() == 0, "root can write to every directory")
    def test_directory_this_user_can_write_is_refused(self) -> None:
        # Group-writable or owner-writable by the job's user is as good
        # as world-writable: every step of the job runs as that user.
        tool = self.make_tool(scratch(self) / "bin", 0o755)
        self.assertTrue(is_untrusted_directory(str(tool.parent)))
        with self.assertRaises(ActionError):
            check_trusted_location(str(tool))

    def test_a_link_from_a_trusted_directory_is_resolved(self) -> None:
        # The trusted directory holds only a symlink; what runs lives
        # where anyone could have put it.
        base = scratch(self)
        planted = self.make_tool(base / "planted", 0o777)
        trusted = base / "trusted"
        trusted.mkdir()
        (trusted / "gpg").symlink_to(planted)
        trusted.chmod(0o555)
        self.addCleanup(trusted.chmod, 0o755)
        with self.assertRaises(ActionError):
            check_trusted_location(str(trusted / "gpg"))


if __name__ == "__main__":
    _ = unittest.main()
