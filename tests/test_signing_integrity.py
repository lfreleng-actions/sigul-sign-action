# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tag payload and publication regressions, using only fixture repositories.

The signature block stands in for Sigul's authenticated response, as in
mock-sigul. These tests check payload preservation and armor boundaries,
not OpenPGP verification, and never invoke Sigul or use a signing key.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import cast
from unittest import mock

from action_common import ActionError
from git_tag import SigningRepository, git_env, read_ref

from tests.helpers import REPOSITORY, git, make_repository, scratch

CONTAINER = REPOSITORY / "scripts" / "container"
if str(CONTAINER) not in sys.path:
    sys.path.insert(0, str(CONTAINER))

import sign_git_tag as container_tag  # noqa: E402

container_main = cast(Callable[[], int], container_tag.main)
SIGNATURE = b"-----BEGIN PGP SIGNATURE-----\n\nfixture\n-----END PGP SIGNATURE-----\n"
TAG = "v1"
REF = "refs/tags/" + TAG


class RepositoryFixture:
    """A workspace tag and the private repository used to sign it."""

    def __init__(self, case: unittest.TestCase) -> None:
        self.base: Path = scratch(case)
        self.workspace: Path = make_repository(self.base / "workspace", tag=TAG)
        self.repo: SigningRepository = SigningRepository(
            self.base / "private" / "repo",
            self.base / "private" / "home",
            self.workspace / ".git",
        )
        self.repo.create()
        self.unsigned: str = self.repo.adopt_workspace_tag(TAG)
        self.body: bytes = self.read_tag(self.unsigned)

    def read_tag(self, oid: str) -> bytes:
        """Read raw bytes: text-mode Git helpers would normalize CRLF."""
        done = subprocess.run(
            ["git", "--no-pager", "cat-file", "tag", oid],
            cwd=self.repo.root,
            env=git_env(self.repo.home, self.repo.objects),
            capture_output=True,
            check=True,
            timeout=10,
        )
        return done.stdout

    def replace_tag(self, body: bytes) -> str:
        """Install exactly these tag bytes in the private repository."""
        path = self.base / "tag-object"
        _ = path.write_bytes(body)
        env = {"GIT_OBJECT_DIRECTORY": str(self.repo.objects)}
        oid = git(self.repo.root, "hash-object", "-t", "tag", "-w", str(path), env=env)
        _ = git(self.repo.root, "update-ref", REF, oid, env=env)
        return oid

    def container_environment(self) -> dict[str, str]:
        """Point the container script's real Git calls only at the fixture."""
        password = self.base / "password"
        _ = password.write_bytes(b"fixture\0")
        return {
            **git_env(self.repo.home, self.repo.objects),
            "GIT_DIR": str(self.repo.root / ".git"),
            "GIT_WORK_TREE": str(self.repo.root),
            "GIT_TAG": TAG,
            "SIGUL_KEY": "fixture-key",
            "SIGUL_PASSWORD": str(password),
            "MAX_RETRIES": "2",
            "RETRY_DELAY": "0",
            "ATTEMPT_TIMEOUT": "0",
        }


class TagIntegrityTests(unittest.TestCase):
    def test_an_appended_signature_preserves_the_original_tag(self) -> None:
        fixture = RepositoryFixture(self)
        signed = fixture.replace_tag(fixture.body + SIGNATURE)
        self.assertEqual(fixture.repo.signed_oid(TAG, fixture.unsigned), signed)
        self.assertEqual(fixture.read_tag(signed), fixture.body + SIGNATURE)

    @unittest.expectedFailure
    def test_unterminated_tag_is_refused_before_signing(self) -> None:
        # A10: appending armor to an unterminated message hides its header
        # in the message's final line; Git then finds no signature.
        fixture = RepositoryFixture(self)
        unsigned = fixture.replace_tag(fixture.body.rstrip(b"\n"))
        with self.assertRaises(ActionError):
            fixture.repo.require_annotated(TAG, unsigned)

    @unittest.expectedFailure
    def test_signed_tag_cannot_change_the_original_payload(self) -> None:
        fixture = RepositoryFixture(self)
        changed = fixture.body.replace(b"tag v1\n", b"tag substituted\n", 1)
        _ = fixture.replace_tag(changed + SIGNATURE)
        with self.assertRaises(ActionError):
            _ = fixture.repo.signed_oid(TAG, fixture.unsigned)

    @unittest.expectedFailure
    def test_signed_payload_is_compared_as_bytes_not_normalized_text(self) -> None:
        fixture = RepositoryFixture(self)
        headers, message = fixture.body.split(b"\n\n", 1)
        original = headers + b"\n\n" + message.replace(b"\n", b"\r\n")
        unsigned = fixture.replace_tag(original)
        _ = fixture.replace_tag(original.replace(b"\r\n", b"\n") + SIGNATURE)
        with self.assertRaises(ActionError):
            _ = fixture.repo.signed_oid(TAG, unsigned)

    @unittest.expectedFailure
    def test_inline_armor_marker_is_not_an_appended_signature(self) -> None:
        fixture = RepositoryFixture(self)
        _ = fixture.replace_tag(fixture.body + b"not an armor boundary: " + SIGNATURE)
        with self.assertRaises(ActionError):
            _ = fixture.repo.signed_oid(TAG, fixture.unsigned)

    @unittest.expectedFailure
    def test_signature_requires_a_closing_armor_boundary(self) -> None:
        fixture = RepositoryFixture(self)
        truncated = SIGNATURE.split(b"-----END PGP SIGNATURE-----", 1)[0]
        _ = fixture.replace_tag(fixture.body + truncated)
        with self.assertRaises(ActionError):
            _ = fixture.repo.signed_oid(TAG, fixture.unsigned)

    @unittest.expectedFailure
    def test_container_refuses_unterminated_tag_without_calling_sigul(self) -> None:
        fixture = RepositoryFixture(self)
        original = fixture.body.rstrip(b"\n")
        unsigned = fixture.replace_tag(original)

        def sign(_argv: list[str], _password: str, _timeout: int) -> int:
            _ = fixture.replace_tag(original + SIGNATURE)
            return 0

        with (
            mock.patch.dict(os.environ, fixture.container_environment(), clear=True),
            mock.patch.object(
                container_tag, "call_with_password", side_effect=sign
            ) as client,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                _ = container_main()
            client.assert_not_called()
        self.assertEqual(fixture.repo.tag_oid(TAG), unsigned)

    @unittest.expectedFailure
    def test_container_rejects_a_ref_update_that_changes_the_payload(self) -> None:
        fixture = RepositoryFixture(self)
        changed = fixture.body.replace(b"tag v1\n", b"tag substituted\n", 1)

        def sign(_argv: list[str], _password: str, _timeout: int) -> int:
            _ = fixture.replace_tag(changed + SIGNATURE)
            return 0

        with (
            mock.patch.dict(os.environ, fixture.container_environment(), clear=True),
            mock.patch.object(
                container_tag, "call_with_password", side_effect=sign
            ) as client,
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                _ = container_main()
            self.assertEqual(client.call_count, 1)
        self.assertEqual(read_ref(fixture.workspace / ".git", REF), fixture.unsigned)


class PushFixture(RepositoryFixture):
    """The signing fixture plus an isolated bare remote."""

    def __init__(self, case: unittest.TestCase) -> None:
        super().__init__(case)
        self.remote: Path = self.base / "remote.git"
        _ = git(
            self.base, "clone", "-q", "--bare", str(self.workspace), str(self.remote)
        )

    def observe_remote(self) -> str:
        return self.repo.fetch_tag(self.remote.as_uri(), TAG)

    def push(self, remote: Path | None = None) -> None:
        self.repo.push_tag(
            self.base.as_uri(),
            (remote or self.remote).as_uri(),
            TAG,
            "fixture-user",
            "fixture-token",
        )


class PushLeaseTests(unittest.TestCase):
    def test_observed_unchanged_remote_accepts_the_signed_tag(self) -> None:
        fixture = PushFixture(self)
        self.assertEqual(fixture.observe_remote(), "")
        signed = fixture.replace_tag(fixture.body + SIGNATURE)
        fixture.push()
        self.assertEqual(read_ref(fixture.remote, REF), signed)
        self.assertFalse((fixture.repo.home / "git-credential").exists())

    @unittest.expectedFailure
    def test_push_requires_a_successful_remote_observation(self) -> None:
        # A11: adopting a local tag does not establish a remote lease.
        fixture = PushFixture(self)
        _ = fixture.replace_tag(fixture.body + SIGNATURE)
        with self.assertRaises(ActionError):
            fixture.push()
        self.assertEqual(read_ref(fixture.remote, REF), fixture.unsigned)

    @unittest.expectedFailure
    def test_failed_fetch_does_not_authorize_a_push(self) -> None:
        fixture = PushFixture(self)
        _ = git(fixture.remote, "update-ref", "-d", REF)
        self.assertNotEqual(fixture.observe_remote(), "")
        _ = git(fixture.remote, "update-ref", REF, fixture.unsigned)
        _ = fixture.replace_tag(fixture.body + SIGNATURE)
        with self.assertRaises(ActionError):
            fixture.push()
        self.assertEqual(read_ref(fixture.remote, REF), fixture.unsigned)

    @unittest.expectedFailure
    def test_push_preserves_a_concurrent_remote_tag_replacement(self) -> None:
        fixture = PushFixture(self)
        self.assertEqual(fixture.observe_remote(), "")
        _ = fixture.replace_tag(fixture.body + SIGNATURE)
        _ = git(fixture.remote, "tag", "-f", "-a", TAG, "-m", "concurrent publisher")
        replacement = read_ref(fixture.remote, REF)
        self.assertNotEqual(replacement, fixture.unsigned)
        with self.assertRaises(ActionError):
            fixture.push()
        self.assertEqual(read_ref(fixture.remote, REF), replacement)

    @unittest.expectedFailure
    def test_push_does_not_recreate_a_concurrently_deleted_tag(self) -> None:
        fixture = PushFixture(self)
        self.assertEqual(fixture.observe_remote(), "")
        _ = fixture.replace_tag(fixture.body + SIGNATURE)
        _ = git(fixture.remote, "update-ref", "-d", REF)
        with self.assertRaises(ActionError):
            fixture.push()
        self.assertIsNone(read_ref(fixture.remote, REF))

    @unittest.expectedFailure
    def test_observation_is_bound_to_the_remote_url(self) -> None:
        fixture = PushFixture(self)
        self.assertEqual(fixture.observe_remote(), "")
        _ = fixture.replace_tag(fixture.body + SIGNATURE)
        other = fixture.base / "other.git"
        _ = git(fixture.base, "clone", "-q", "--bare", str(fixture.remote), str(other))
        with self.assertRaises(ActionError):
            fixture.push(other)
        self.assertEqual(read_ref(other, REF), fixture.unsigned)


if __name__ == "__main__":
    _ = unittest.main()
