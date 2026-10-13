# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the shared fixtures in tests/helpers.py."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from tests.helpers import git, make_repository, scratch


class FixtureGitIsolationTests(unittest.TestCase):
    def test_inherited_git_variables_cannot_redirect_fixtures(self) -> None:
        # git exports GIT_DIR and GIT_INDEX_FILE to hooks, so a suite run
        # from inside one inherits them pointing at the caller's repository.
        outside = make_repository(scratch(self) / "outside")
        before = git(outside, "rev-parse", "HEAD")
        fixture = scratch(self) / "fixture"
        inherited = {
            "GIT_DIR": str(outside / ".git"),
            "GIT_WORK_TREE": str(outside),
            "GIT_INDEX_FILE": str(outside / ".git" / "index"),
        }
        with mock.patch.dict(os.environ, inherited):
            _ = make_repository(fixture, tag="v1")
        self.assertEqual(git(outside, "rev-parse", "HEAD"), before)
        self.assertEqual(git(outside, "tag", "--list"), "")
        self.assertTrue((fixture / ".git").is_dir())
        self.assertEqual(git(fixture, "tag", "--list"), "v1")


if __name__ == "__main__":
    _ = unittest.main()
