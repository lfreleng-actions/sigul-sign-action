# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Shared fixtures for the unit tests."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
PINS_DIR = REPOSITORY / "containers"

# Identity and signing settings for fixture repositories, so a
# developer's own git configuration (tag.gpgSign, say) cannot change
# what a test builds.
GIT_FIXTURE_ENV = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.org",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.org",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
}


def scratch(case: unittest.TestCase) -> Path:
    """Return a temporary directory removed when the test ends.

    Under /tmp, and resolved, because gpg-agent's socket path is length
    limited and macOS's TMPDIR is long and reached through a symlink.
    """
    path = Path(tempfile.mkdtemp(prefix="sigul-test.", dir="/tmp")).resolve()
    case.addCleanup(shutil.rmtree, path, True)
    return path


def git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    """Run git in a fixture repository and return its stripped output."""
    full = dict(os.environ, **GIT_FIXTURE_ENV, **(env or {}))
    done = subprocess.run(
        ["git", *args], cwd=cwd, env=full, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def make_repository(path: Path, tag: str = "", annotated: bool = True) -> Path:
    """Create a repository with one commit and, optionally, a tag."""
    path.mkdir(parents=True, exist_ok=True)
    _ = git(path, "init", "-q")
    _ = (path / "file").write_text("content\n")
    _ = git(path, "add", "file")
    _ = git(path, "commit", "-qm", "initial")
    if tag:
        if annotated:
            _ = git(path, "tag", "-a", tag, "-m", f"tag {tag}")
        else:
            _ = git(path, "tag", tag)
    return path


def base_env(workspace: Path, **overrides: str) -> dict[str, str]:
    """Return the environment action.yaml gives the validation step."""
    env = {
        "GITHUB_WORKSPACE": str(workspace),
        "SIGN_TYPE": "sign-data",
        "SIGN_OBJECT": "a.txt",
        "SIGUL_KEY_NAME": "release-key",
        "HAVE_SIGUL_CONF": "true",
        "HAVE_SIGUL_PASS": "true",
        "HAVE_SIGUL_PKI": "true",
        "HAVE_GH_KEY": "false",
        "HOSTS_ENTRY": "auto",
        "PUSH_TAG": "true",
        "DRY_RUN": "false",
        "MAX_RETRIES": "5",
        "RETRY_DELAY": "15",
        "ATTEMPT_TIMEOUT": "600",
        "EXCLUDE_GLOBS": "*.asc\n*.md5\nmaven-metadata.xml\n",
        "GH_USER": "octocat",
    }
    env.update(overrides)
    return env
