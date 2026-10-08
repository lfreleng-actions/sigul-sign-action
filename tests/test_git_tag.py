# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/git_tag.py."""

from __future__ import annotations

import io
import os
import subprocess
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from action_common import SYSTEM_PATH, ActionError
from git_tag import (
    PGP_SIGNATURE_MARKER,
    SigningRepository,
    check_tag_name,
    read_extension,
    read_head,
    read_ref,
    uses_reftable,
    uses_sha256,
    workspace_git_dir,
    write_tag_ref,
)

from tests.git_http_server import GitServer
from tests.helpers import git, make_repository, scratch

SIGNATURE = f"{PGP_SIGNATURE_MARKER}\n\nfixture\n-----END PGP SIGNATURE-----\n"


class TagNameTests(unittest.TestCase):
    def test_valid_names(self) -> None:
        for name in ("v1.0.0", "release/2026.10", "1.2.3-rc1"):
            check_tag_name(name)

    def test_invalid_names(self) -> None:
        for name in (
            "HEAD:refs/heads/main",
            "a..b",
            "two words",
            "new\nline",
            "end.lock",
            "a~1",
            "a^",
            "@{x}",
        ):
            with self.subTest(name=name), self.assertRaises(ActionError):
                check_tag_name(name)


class RefFileTests(unittest.TestCase):
    def test_loose_and_packed_refs(self) -> None:
        repo = make_repository(scratch(self) / "repo", tag="v1")
        git_dir = repo / ".git"
        loose = git(repo, "rev-parse", "refs/tags/v1")
        self.assertEqual(read_ref(git_dir, "refs/tags/v1"), loose)
        _ = git(repo, "pack-refs", "--all")
        self.assertFalse((git_dir / "refs" / "tags" / "v1").exists())
        self.assertEqual(read_ref(git_dir, "refs/tags/v1"), loose)
        self.assertIsNone(read_ref(git_dir, "refs/tags/absent"))

    def test_head(self) -> None:
        repo = make_repository(scratch(self) / "repo")
        commit = git(repo, "rev-parse", "HEAD")
        self.assertEqual(read_head(repo / ".git"), commit)
        _ = git(repo, "checkout", "-q", "--detach")
        self.assertEqual(read_head(repo / ".git"), commit)

    def test_write_tag_ref(self) -> None:
        repo = make_repository(scratch(self) / "repo", tag="v1")
        commit = git(repo, "rev-parse", "HEAD")
        write_tag_ref(repo / ".git", "release/v2", commit)
        self.assertEqual(git(repo, "rev-parse", "refs/tags/release/v2"), commit)
        mode = (
            repo / ".git" / "refs" / "tags" / "release" / "v2"
        ).stat().st_mode & 0o777
        self.assertEqual(mode, 0o644)
        with self.assertRaises(ActionError):
            write_tag_ref(repo / ".git", "v3", "not-an-object-id")

    def test_write_tag_ref_refuses_symlinks(self) -> None:
        base = scratch(self)
        repo = make_repository(base / "repo")
        commit = git(repo, "rev-parse", "HEAD")
        elsewhere = base / "elsewhere"
        elsewhere.mkdir()
        tags = repo / ".git" / "refs" / "tags"
        tags.rmdir()
        tags.symlink_to(elsewhere)
        with self.assertRaises(ActionError):
            write_tag_ref(repo / ".git", "v1", commit)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_standard_checkout_only(self) -> None:
        base = scratch(self)
        repo = make_repository(base / "repo")
        self.assertEqual(workspace_git_dir(repo), repo / ".git")
        self.assertFalse(uses_sha256(repo / ".git"))
        self.assertFalse(uses_reftable(repo / ".git"))
        _ = (repo / ".git" / "config").write_text(
            "[extensions]\n\tobjectformat = sha256\n"
        )
        self.assertTrue(uses_sha256(repo / ".git"))
        # Refused where validation runs, before any credential exists,
        # not later in the signing step.
        with self.assertRaises(ActionError) as caught:
            _ = workspace_git_dir(repo)
        self.assertIn("SHA-256", str(caught.exception))

    def test_borrowed_object_store_is_refused(self) -> None:
        repo = make_repository(scratch(self) / "repo")
        info = repo / ".git" / "objects" / "info"
        info.mkdir(exist_ok=True)
        _ = (info / "alternates").write_text("/elsewhere/objects\n")
        with self.assertRaises(ActionError) as caught:
            _ = workspace_git_dir(repo)
        self.assertIn("alternates", str(caught.exception))

    def test_reftable_repository_is_refused(self) -> None:
        repo = make_repository(scratch(self) / "repo")
        _ = (repo / ".git" / "config").write_text(
            "[core]\n\trepositoryformatversion = 1\n[extensions]\n\trefStorage = reftable\n"
        )
        self.assertTrue(uses_reftable(repo / ".git"))
        with self.assertRaises(ActionError) as caught:
            _ = workspace_git_dir(repo)
        self.assertIn("reftables", str(caught.exception))

    def test_extension_values_are_read_as_git_reads_them(self) -> None:
        # Quoted, commented, and in any case: each is valid to git, and a
        # check that missed one would let the repository through.
        repo = make_repository(scratch(self) / "repo")
        config = repo / ".git" / "config"
        remote = '[remote "origin"]\n\turl = https://x/y.git\n'
        for text, expected in (
            ('[extensions]\n\trefStorage = "reftable"\n', ("", "reftable")),
            ("[extensions]\n\tobjectformat = sha256 ; a comment\n", ("sha256", "")),
            ("[extensions]\n\tobjectFormat = sha256   # a comment\n", ("sha256", "")),
            ("[Extensions]\n\tREFSTORAGE = REFTABLE\n", ("", "reftable")),
            (remote + "[extensions]\n\tobjectformat = sha1\n", ("sha1", "")),
            (remote, ("", "")),
        ):
            with self.subTest(text=text):
                _ = config.write_text(text)
                self.assertEqual(
                    (
                        read_extension(repo / ".git", "objectformat"),
                        read_extension(repo / ".git", "refstorage"),
                    ),
                    expected,
                )
        # What cannot be parsed is refused, not passed.
        _ = config.write_text("not a git config\n")
        with self.assertRaises(ActionError):
            _ = read_extension(repo / ".git", "objectformat")


class ConfigurationRegressionTests(unittest.TestCase):
    @unittest.expectedFailure
    def test_extension_sections_use_git_case_and_last_value_precedence(self) -> None:
        base = scratch(self)
        repo = make_repository(base / "repo")
        config = repo / ".git" / "config"
        for name, first, last in (
            ("refStorage", "files", "reftable"),
            ("objectFormat", "sha1", "sha256"),
        ):
            with self.subTest(extension=name):
                _ = config.write_text(
                    f"[extensions]\n{name} = {first}\n[Extensions]\n{name} = {last}\n"
                )
                # A12: query an explicit file outside the workspace repo,
                # so Git's parser is the oracle, not configparser's INI rules.
                expected = git(
                    base, "config", "--file", str(config), "--get", f"extensions.{name}"
                )
                self.assertEqual(read_extension(repo / ".git", name), expected)
                with self.assertRaises(ActionError):
                    _ = workspace_git_dir(repo)

    @unittest.expectedFailure
    def test_extension_values_follow_git_quoting_comments_and_continuations(
        self,
    ) -> None:
        base = scratch(self)
        repo = make_repository(base / "repo")
        config = repo / ".git" / "config"
        for value in ('reftab"le"', "reftable#comment", "ref\\\ntable"):
            with self.subTest(value=value):
                _ = config.write_text(f"[extensions]\nrefStorage = {value}\n")
                expected = git(
                    base,
                    "config",
                    "--file",
                    str(config),
                    "--get",
                    "extensions.refStorage",
                )
                self.assertEqual(expected, "reftable")
                self.assertEqual(read_extension(repo / ".git", "refStorage"), expected)

    @unittest.expectedFailure
    def test_git_invalid_config_is_refused_even_when_ini_accepts_it(self) -> None:
        base = scratch(self)
        repo = make_repository(base / "repo")
        config = repo / ".git" / "config"
        _ = config.write_text('[extensions]\nrefStorage = "reftable\\q"\n')
        with self.assertRaises(subprocess.CalledProcessError):
            _ = git(base, "config", "--file", str(config), "--list")
        with self.assertRaises(ActionError):
            _ = workspace_git_dir(repo)

    @unittest.expectedFailure
    def test_unconditional_and_conditional_includes_are_refused(self) -> None:
        repo = make_repository(scratch(self) / "repo")
        config = repo / ".git" / "config"
        original = config.read_text()
        _ = (repo / ".git" / "extra.config").write_text(
            "[extensions]\nrefStorage = reftable\n"
        )
        # Include conditions would be evaluated in the private repository,
        # not the workspace. Refuse includes instead of silently missing them.
        for section in ("include", 'includeIf "gitdir:**/repo/.git"'):
            with self.subTest(section=section):
                _ = config.write_text(original + f"[{section}]\npath = extra.config\n")
                with self.assertRaises(ActionError):
                    _ = workspace_git_dir(repo)


class SigningRepositoryTests(unittest.TestCase):
    def setup_remote(self) -> tuple[Path, Path, Path]:
        """A bare 'GitHub' repository, and a shallow workspace clone of it
        whose tag differs from the remote's."""
        base = scratch(self)
        seed = make_repository(base / "seed", tag="v1.0.0")
        remote = base / "remote.git"
        _ = git(base, "init", "-q", "--bare", "--initial-branch=main", str(remote))
        _ = git(
            seed, "push", "-q", str(remote), "HEAD:refs/heads/main", "refs/tags/v1.0.0"
        )
        workspace = base / "workspace"
        _ = git(base, "clone", "-q", "--depth", "1", f"file://{remote}", str(workspace))
        _ = git(
            workspace, "tag", "-f", "-a", "v1.0.0", "-m", "the workspace's own copy"
        )
        return base, remote, workspace

    def repository(self, base: Path, workspace: Path) -> SigningRepository:
        repo = SigningRepository(
            base / "work" / "repo", base / "work" / "home", workspace / ".git"
        )
        repo.create()
        return repo

    @unittest.expectedFailure
    def test_shared_object_store_disables_automatic_maintenance(self) -> None:
        base = scratch(self)
        workspace = make_repository(base / "workspace")
        repo = self.repository(base, workspace)
        settings = dict(
            line.split("=", 1)
            for line in git(repo.root, "config", "--local", "--list").splitlines()
        )
        # A03: older fetches run gc --auto; newer Git has additional
        # maintenance tasks. Neither may prune using only the private refs.
        self.assertEqual(
            (settings.get("gc.auto"), settings.get("maintenance.auto")), ("0", "false")
        )

    def test_fetched_tag_replaces_the_local_one(self) -> None:
        base, remote, workspace = self.setup_remote()
        repo = self.repository(base, workspace)
        self.assertTrue((repo.root / ".git" / "shallow").is_file())
        self.assertEqual(repo.fetch_tag(f"file://{remote}", "v1.0.0"), "")
        self.assertEqual(
            repo.tag_oid("v1.0.0"), git(remote, "rev-parse", "refs/tags/v1.0.0")
        )
        # A real run adds the fetched objects to the workspace's store,
        # where the recorded ref will need them, but moves no ref there.
        self.assertNotEqual(
            git(workspace, "rev-parse", "refs/tags/v1.0.0"), repo.tag_oid("v1.0.0")
        )

    def test_isolated_repository_leaves_the_workspace_store_alone(self) -> None:
        # A dry run fetches into an object store of its own, reading the
        # workspace's through an alternate, so not a byte is added there.
        base, remote, workspace = self.setup_remote()
        store = workspace / ".git" / "objects"
        before = sorted(str(p.relative_to(store)) for p in store.rglob("*"))
        repo = SigningRepository(
            base / "work" / "repo",
            base / "work" / "home",
            workspace / ".git",
            isolated=True,
        )
        repo.create()
        self.assertEqual(repo.fetch_tag(f"file://{remote}", "v1.0.0"), "")
        fetched = repo.tag_oid("v1.0.0")
        self.assertEqual(fetched, git(remote, "rev-parse", "refs/tags/v1.0.0"))
        assert fetched is not None
        repo.require_annotated("v1.0.0", fetched)
        # The workspace's own commit is still readable, by alternate.
        head = git(workspace, "rev-parse", "HEAD")
        self.assertEqual(repo.object_type(head), "commit")
        after = sorted(str(p.relative_to(store)) for p in store.rglob("*"))
        self.assertEqual(before, after)

    def test_workspace_configuration_is_never_read(self) -> None:
        base, remote, workspace = self.setup_remote()
        # Were the workspace's configuration consulted, this rewrite would
        # send the fetch somewhere that does not exist.
        _ = git(workspace, "config", "url.file:///nonexistent/.insteadOf", "file://")
        repo = self.repository(base, workspace)
        self.assertEqual(repo.fetch_tag(f"file://{remote}", "v1.0.0"), "")

    def test_falls_back_to_the_workspace_tag(self) -> None:
        base, _remote, workspace = self.setup_remote()
        repo = self.repository(base, workspace)
        reason = repo.fetch_tag(f"file://{base}/no-such-remote.git", "v1.0.0")
        self.assertNotEqual(reason, "")
        oid = repo.adopt_workspace_tag("v1.0.0")
        self.assertEqual(oid, git(workspace, "rev-parse", "refs/tags/v1.0.0"))
        repo.require_annotated("v1.0.0", oid)
        with self.assertRaises(ActionError):
            _ = repo.adopt_workspace_tag("v9.9.9")

    def test_lightweight_tag_is_refused(self) -> None:
        base = scratch(self)
        workspace = make_repository(base / "workspace", tag="light", annotated=False)
        repo = self.repository(base, workspace)
        oid = repo.adopt_workspace_tag("light")
        with self.assertRaises(ActionError) as caught:
            repo.require_annotated("light", oid)
        self.assertIn("not an annotated tag", str(caught.exception))

    def test_sign_record_and_push(self) -> None:
        base, remote, workspace = self.setup_remote()
        repo = self.repository(base, workspace)
        _ = repo.fetch_tag(f"file://{remote}", "v1.0.0")
        unsigned = repo.tag_oid("v1.0.0")
        assert unsigned is not None
        with self.assertRaises(ActionError):
            _ = repo.signed_oid("v1.0.0", unsigned)

        # Sign as sigul does, with the same object store: append a
        # signature to the tag object and move the ref.
        sigul_env = {"GIT_OBJECT_DIRECTORY": str(repo.objects)}
        body = git(repo.root, "cat-file", "tag", unsigned, env=sigul_env) + "\n"
        signed_path = base / "signed"
        _ = signed_path.write_text(body + SIGNATURE)
        signed = git(
            repo.root, "hash-object", "-t", "tag", "-w", str(signed_path), env=sigul_env
        )
        _ = git(
            repo.root, "update-ref", "refs/tags/v1.0.0", signed, unsigned, env=sigul_env
        )

        self.assertEqual(repo.signed_oid("v1.0.0", unsigned), signed)
        write_tag_ref(workspace / ".git", "v1.0.0", signed)
        self.assertEqual(git(workspace, "rev-parse", "refs/tags/v1.0.0"), signed)
        _ = git(workspace, "fsck", "--no-dangling")

        repo.push_tag(
            f"file://{base}", f"file://{remote}", "v1.0.0", "octocat", "not-a-token"
        )
        self.assertEqual(git(remote, "rev-parse", "refs/tags/v1.0.0"), signed)
        self.assertFalse((repo.home / "git-credential").exists())


class AuthenticatedPushTests(unittest.TestCase):
    """Push over HTTP to a server that demands the configured token, as
    GitHub does: a file:// remote never asks for credentials at all."""

    def prepare(self) -> tuple[SigningRepository, GitServer, str]:
        base = scratch(self)
        root = base / "served"
        root.mkdir()
        remote = root / "org" / "repo.git"
        remote.parent.mkdir()
        _ = git(base, "init", "-q", "--bare", "--initial-branch=main", str(remote))
        workspace = make_repository(base / "workspace", tag="v1.0.0")
        repo = SigningRepository(
            base / "work" / "repo", base / "work" / "home", workspace / ".git"
        )
        repo.create()
        oid = repo.adopt_workspace_tag("v1.0.0")
        server = GitServer(root, "octocat", "the-token")
        server.start()
        self.addCleanup(server.stop)
        return repo, server, oid

    def push(self, repo: SigningRepository, scope: str, url: str, token: str) -> None:
        with redirect_stderr(io.StringIO()):
            repo.push_tag(scope, url, "v1.0.0", "octocat", token)

    def test_helper_supplies_the_configured_user_and_token(self) -> None:
        repo, server, oid = self.prepare()
        self.push(repo, server.url, f"{server.url}/org/repo.git", "the-token")
        remote = server.root / "org" / "repo.git"
        self.assertEqual(git(remote, "rev-parse", "refs/tags/v1.0.0"), oid)
        self.assertIn(server.expected, server.seen)
        self.assertFalse((repo.home / "git-credential").exists())

    def test_a_wrong_token_is_refused(self) -> None:
        repo, server, _oid = self.prepare()
        with self.assertRaises(ActionError):
            self.push(repo, server.url, f"{server.url}/org/repo.git", "not-the-token")
        self.assertNotIn(server.expected, server.seen)

    def test_the_helper_answers_only_its_own_server(self) -> None:
        # Scoped to another host, the helper is never asked, so the push
        # carries no credentials and the server refuses it.
        repo, server, _oid = self.prepare()
        with self.assertRaises(ActionError):
            self.push(
                repo, "https://github.com", f"{server.url}/org/repo.git", "the-token"
            )
        self.assertTrue(all(seen == "" for seen in server.seen))

    def test_the_helper_runs_no_tool_a_step_could_plant(self) -> None:
        # git runs the helper through sh with the system PATH, where a
        # world-writable /usr/local/bin comes first on hosted runners.
        # Plant the tools a helper might reach for, each recording the
        # token it was handed, ahead of everything: the push must still
        # succeed, and none of them may run.
        repo, server, oid = self.prepare()
        planted = scratch(self) / "bin"
        planted.mkdir()
        trap = planted / "ran"
        for tool in ("cat", "head", "sed", "awk", "printf", "read", "test"):
            path = planted / tool
            _ = path.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{trap}"\nexit 1\n')
            path.chmod(0o755)
        with mock.patch(
            "action_common.SYSTEM_PATH", f"{planted}{os.pathsep}{SYSTEM_PATH}"
        ):
            self.push(repo, server.url, f"{server.url}/org/repo.git", "the-token")
        remote = server.root / "org" / "repo.git"
        self.assertEqual(git(remote, "rev-parse", "refs/tags/v1.0.0"), oid)
        self.assertIn(server.expected, server.seen)
        self.assertFalse(trap.exists(), trap.read_text() if trap.exists() else "")


if __name__ == "__main__":
    _ = unittest.main()
