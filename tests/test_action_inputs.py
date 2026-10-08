# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/action_inputs.py."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from action_common import ActionError, InputError, Messages
from action_inputs import build_plan, parse_bool, parse_int
from client_image import read_pin, resolve_hosts, resolve_image, split_reference
from sign_targets import plan_sign_data

from tests.helpers import PINS_DIR, base_env, make_repository, scratch

DIGEST = "sha256:" + "a" * 64
DEFAULT_EXCLUDES = ["*.asc", "*.md5", "*.sha1", "maven-metadata.xml"]


class ScalarTests(unittest.TestCase):
    def test_booleans(self) -> None:
        self.assertTrue(parse_bool("dry-run", "true"))
        self.assertTrue(parse_bool("dry-run", " TRUE "))
        self.assertFalse(parse_bool("dry-run", "false"))
        for raw in ("yes", "1", ""):
            with self.assertRaises(InputError):
                _ = parse_bool("dry-run", raw)

    def test_integers(self) -> None:
        self.assertEqual(parse_int("max-retries", "5", 1), 5)
        self.assertEqual(parse_int("retry-delay", "0", 0), 0)
        for raw in ("many", "-1", "1.5", ""):
            with self.assertRaises(InputError):
                _ = parse_int("retry-delay", raw, 0)
        with self.assertRaises(InputError):
            _ = parse_int("max-retries", "0", 1)


class ImageTests(unittest.TestCase):
    def test_split_reference(self) -> None:
        self.assertEqual(split_reference("a/b"), ("a/b", "", ""))
        self.assertEqual(split_reference("a/b:1.0"), ("a/b", "1.0", ""))
        self.assertEqual(split_reference(f"a/b@{DIGEST}"), ("a/b", "", DIGEST))
        self.assertEqual(split_reference(f"a/b:1@{DIGEST}"), ("a/b", "1", DIGEST))
        # A registry port is not a tag.
        self.assertEqual(
            split_reference("localhost:5000/b"), ("localhost:5000/b", "", "")
        )

    def test_built_in_pins_parse(self) -> None:
        for name in ("legacy", "modern"):
            reference = read_pin(PINS_DIR / name / "Dockerfile")
            _name, tag, digest = split_reference(reference)
            self.assertTrue(tag, f"{name} pin has no tag")
            self.assertTrue(digest.startswith("sha256:"), f"{name} pin has no digest")

    def test_pin_without_digest_is_rejected(self) -> None:
        pin = scratch(self) / "Dockerfile"
        _ = pin.write_text("# comment\nFROM docker.io/lfreleng/sigul:0.2.0\n")
        with self.assertRaises(ActionError):
            _ = read_pin(pin)

    def test_pin_with_platform_flag(self) -> None:
        pin = scratch(self) / "Dockerfile"
        _ = pin.write_text(f"FROM --platform=linux/amd64 example.org/c:1@{DIGEST}\n")
        self.assertEqual(read_pin(pin), f"example.org/c:1@{DIGEST}")

    def test_default_is_legacy(self) -> None:
        image = resolve_image("", "", "", "", PINS_DIR)
        self.assertEqual(image.source, "legacy")
        self.assertEqual(image.reference, read_pin(PINS_DIR / "legacy" / "Dockerfile"))

    def test_nicknames(self) -> None:
        self.assertEqual(resolve_image("modern", "", "", "", PINS_DIR).source, "modern")
        self.assertEqual(
            resolve_image(" Legacy ", "", "", "", PINS_DIR).source, "legacy"
        )
        with self.assertRaises(InputError):
            _ = resolve_image("k8s", "", "", "", PINS_DIR)

    def test_nickname_and_bespoke_are_exclusive(self) -> None:
        for image, tag, digest in (("x/y", "", ""), ("", "1", ""), ("", "", DIGEST)):
            with self.assertRaises(InputError) as caught:
                _ = resolve_image("legacy", image, tag, digest, PINS_DIR)
            self.assertIn("not both", str(caught.exception))

    def test_bespoke_images(self) -> None:
        image = resolve_image("", "ghcr.io/org/client", "v1", "", PINS_DIR)
        self.assertEqual(
            (image.reference, image.source), ("ghcr.io/org/client:v1", "bespoke")
        )
        self.assertFalse(image.has_digest)
        image = resolve_image("", "ghcr.io/org/client", "v1", DIGEST, PINS_DIR)
        self.assertEqual(image.reference, f"ghcr.io/org/client:v1@{DIGEST}")
        self.assertTrue(image.has_digest)
        image = resolve_image("", f"ghcr.io/org/client@{DIGEST}", "", "", PINS_DIR)
        self.assertEqual(image.reference, f"ghcr.io/org/client@{DIGEST}")

    def test_bespoke_image_rejections(self) -> None:
        cases = [
            ("", "1", ""),  # a tag with no image
            ("ghcr.io/org/client", "", ""),  # neither tag nor digest
            ("ghcr.io/org/client:v1", "v2", ""),  # tag given twice
            (f"ghcr.io/org/client@{DIGEST}", "", DIGEST),  # digest given twice
            ("ghcr.io/Org/Client", "v1", ""),  # upper case in the path
            ("--privileged", "v1", ""),  # an option, not an image
            ("ghcr.io/org/client", "v1", "sha256:short"),
            ("ghcr.io/org/client", "bad tag", ""),
        ]
        for image, tag, digest in cases:
            with self.subTest(image=image, tag=tag, digest=digest):
                with self.assertRaises(InputError):
                    _ = resolve_image("", image, tag, digest, PINS_DIR)


class HostsTests(unittest.TestCase):
    def test_auto_applies_for_legacy(self) -> None:
        messages = Messages()
        hosts = resolve_hosts(
            "auto", "192.0.2.1", "bridge.example.org", "legacy", messages
        )
        self.assertEqual(
            [(h.name, h.address) for h in hosts], [("bridge.example.org", "192.0.2.1")]
        )
        self.assertEqual((messages.warnings, messages.notices), ([], []))

    def test_auto_takes_several_names(self) -> None:
        hosts = resolve_hosts(
            "auto", "2001:db8::1", "a.example.org b", "legacy", Messages()
        )
        self.assertEqual([h.name for h in hosts], ["a.example.org", "b"])

    def test_addresses_are_canonical(self) -> None:
        # As getaddrinfo() spells them, so the DNS comparison is of
        # addresses and a legitimate spelling draws no stale warning.
        for raw, canonical in (
            ("2001:0db8:0000::0001", "2001:db8::1"),
            ("2001:DB8::1", "2001:db8::1"),
            ("192.0.2.1", "192.0.2.1"),
        ):
            hosts = resolve_hosts("auto", raw, "a", "legacy", Messages())
            self.assertEqual(hosts[0].address, canonical, raw)

    def test_auto_skips_unusable_values_with_a_warning(self) -> None:
        for address, names in (
            ("not-an-ip", "a.example.org"),
            ("192.0.2.1", ""),
            ("", "a"),
            ("192.0.2.1", "https://a/"),
        ):
            messages = Messages()
            self.assertEqual(
                resolve_hosts("auto", address, names, "legacy", messages), ()
            )
            self.assertEqual(len(messages.warnings), 1, (address, names))

    def test_auto_ignores_other_containers(self) -> None:
        for source in ("modern", "bespoke"):
            messages = Messages()
            self.assertEqual(
                resolve_hosts("auto", "192.0.2.1", "a", source, messages), ()
            )
            self.assertIn("sigul-hosts-entry: true", messages.notices[0])

    def test_nothing_supplied_says_nothing(self) -> None:
        messages = Messages()
        self.assertEqual(resolve_hosts("auto", "", "", "modern", messages), ())
        self.assertEqual(resolve_hosts("auto", "", "", "legacy", messages), ())
        self.assertEqual((messages.warnings, messages.notices), ([], []))

    def test_explicit_true_and_false(self) -> None:
        hosts = resolve_hosts("true", "192.0.2.1", "a", "modern", Messages())
        self.assertEqual(len(hosts), 1)
        messages = Messages()
        self.assertEqual(
            resolve_hosts("false", "192.0.2.1", "a", "legacy", messages), ()
        )
        self.assertEqual(len(messages.notices), 1)
        for address, names in (("", "a"), ("bad", "a")):
            with self.assertRaises(InputError):
                _ = resolve_hosts("true", address, names, "modern", Messages())
        with self.assertRaises(InputError):
            _ = resolve_hosts("sometimes", "", "", "legacy", Messages())


class SignDataTests(unittest.TestCase):
    def workspace(self) -> Path:
        root = scratch(self) / "workspace"
        (root / "dist" / "nested").mkdir(parents=True)
        for name in (
            "dist/a.jar",
            "dist/b.pom",
            "dist/nested/c.jar",
            "dist/a.jar.md5",
            "dist/maven-metadata.xml",
            "top.txt",
        ):
            _ = (root / name).write_text(name)
        return root

    def plan(
        self, root: Path, sign_object: str, messages: Messages | None = None
    ) -> list[tuple[str, str]]:
        targets = plan_sign_data(
            sign_object, root, DEFAULT_EXCLUDES, messages or Messages()
        )
        real = os.path.realpath(root)
        return [
            (os.path.relpath(t.source, real), os.path.relpath(t.output, real))
            for t in targets
        ]

    def test_single_file(self) -> None:
        root = self.workspace()
        self.assertEqual(self.plan(root, "top.txt"), [("top.txt", "top.txt.asc")])

    def test_legacy_workspace_path_and_blank_lines(self) -> None:
        root = self.workspace()
        got = self.plan(root, "\n/github/workspace/top.txt\n\n   \ndist/a.jar\n")
        self.assertEqual([source for source, _ in got], ["top.txt", "dist/a.jar"])

    def test_directory_honours_exclusions_and_recurses(self) -> None:
        root = self.workspace()
        got = [source for source, _ in self.plan(root, "dist")]
        self.assertEqual(got, ["dist/a.jar", "dist/b.pom", "dist/nested/c.jar"])

    def test_directory_skips_symlinks_and_special_files(self) -> None:
        root = self.workspace()
        (root / "dist" / "link.jar").symlink_to(root / "top.txt")
        os.mkfifo(root / "dist" / "pipe")
        got = [source for source, _ in self.plan(root, "dist")]
        self.assertEqual(got, ["dist/a.jar", "dist/b.pom", "dist/nested/c.jar"])

    def test_wildcards(self) -> None:
        root = self.workspace()
        messages = Messages()
        # Two words on one line, each expanded; directories are skipped.
        got = [s for s, _ in self.plan(root, "dist/*.jar top.*\ndist/*", messages)]
        self.assertEqual(
            got,
            [
                "dist/a.jar",
                "top.txt",
                "dist/a.jar.md5",
                "dist/b.pom",
                "dist/maven-metadata.xml",
            ],
        )
        self.assertEqual(messages.warnings, [])

    def test_unmatched_wildcard_warns(self) -> None:
        root = self.workspace()
        messages = Messages()
        _ = self.plan(root, "top.txt\nnothing/*.zip", messages)
        self.assertEqual(messages.warnings, ["No regular files match: nothing/*.zip"])
        with self.assertRaises(InputError):
            _ = self.plan(root, "nothing/*.zip")

    def test_never_signs_a_signature_this_run_replaces(self) -> None:
        root = self.workspace()
        _ = (root / "dist" / "a.jar.asc").write_text("stale")
        got = [s for s, _ in self.plan(root, "dist/a.jar*")]
        self.assertEqual(got, ["dist/a.jar", "dist/a.jar.md5"])

    def test_a_symlinked_stale_signature_is_not_signed_either(self) -> None:
        # The stale signature is a symlink to another file: its target
        # must not be signed into a.jar.asc.asc.
        root = self.workspace()
        (root / "dist" / "a.jar.asc").symlink_to(root / "top.txt")
        got = [s for s, _ in self.plan(root, "dist/a.jar*")]
        self.assertEqual(got, ["dist/a.jar", "dist/a.jar.md5"])

    def test_never_signs_through_a_link_to_a_planned_signature(self) -> None:
        root = self.workspace()
        _ = (root / "dist" / "a.jar.asc").write_text("stale")
        (root / "alias.asc").symlink_to(root / "dist" / "a.jar.asc")
        got = [s for s, _ in self.plan(root, "dist/a.jar\nalias.asc")]
        self.assertEqual(got, ["dist/a.jar"])

    def test_duplicates_collapse(self) -> None:
        root = self.workspace()
        self.assertEqual(len(self.plan(root, "top.txt\n./top.txt\n*.txt")), 1)

    def test_symlink_inside_workspace_signs_beside_the_link(self) -> None:
        root = self.workspace()
        (root / "alias.jar").symlink_to(root / "dist" / "a.jar")
        self.assertEqual(
            self.plan(root, "alias.jar"), [("dist/a.jar", "alias.jar.asc")]
        )

    def test_rejections(self) -> None:
        root = self.workspace()
        outside = scratch(self) / "outside.txt"
        _ = outside.write_text("x")
        (root / "escape.txt").symlink_to(outside)
        (root / "dir-link").symlink_to(root / "dist")
        os.mkfifo(root / "fifo")
        (root / "taken.txt.asc").mkdir()
        _ = (root / "taken.txt").write_text("x")
        (root / "tree").mkdir()
        _ = (root / "tree" / "artifact").write_text("x")
        (root / "tree" / "artifact.asc").mkdir()
        # A link outside the workspace to a file inside it: the target is
        # readable, but its signature would land outside the mount.
        external = scratch(self) / "external.txt"
        external.symlink_to(root / "top.txt")
        cases = {
            "missing.txt": "Not a regular file or directory",
            str(outside): "outside the workspace",
            "escape.txt": "outside the workspace",
            str(external): "could not be written",
            "dir-link": "symlink to a directory",
            "fifo": "Not a regular file or directory",
            "taken.txt": "over the directory",
            # The same, met while walking a directory.
            "tree": "over the directory",
        }
        for entry, expected in cases.items():
            with self.subTest(entry=entry):
                with self.assertRaises(InputError) as caught:
                    _ = self.plan(root, entry)
                self.assertIn(expected, str(caught.exception))

    def test_every_error_is_reported(self) -> None:
        root = self.workspace()
        with self.assertRaises(InputError) as caught:
            _ = self.plan(root, "one.txt\ntop.txt\ntwo.txt")
        self.assertEqual(len(str(caught.exception).splitlines()), 2)


class BuildPlanTests(unittest.TestCase):
    def test_defaults_reproduce_the_legacy_action(self) -> None:
        root = scratch(self)
        _ = (root / "a.txt").write_text("a")
        plan = build_plan(base_env(root), PINS_DIR)
        self.assertEqual(plan.sign_type, "sign-data")
        self.assertEqual(plan.image.source, "legacy")
        self.assertFalse(plan.dry_run)
        self.assertEqual(len(plan.targets), 1)
        self.assertEqual(
            (plan.max_retries, plan.retry_delay, plan.attempt_timeout), (5, 15, 600)
        )

    def test_attempt_timeout(self) -> None:
        root = scratch(self)
        _ = (root / "a.txt").write_text("a")
        plan = build_plan(base_env(root, ATTEMPT_TIMEOUT="0"), PINS_DIR)
        self.assertEqual(plan.attempt_timeout, 0)
        for raw in ("-1", "soon", "1.5"):
            with self.subTest(raw=raw), self.assertRaises(InputError):
                _ = build_plan(base_env(root, ATTEMPT_TIMEOUT=raw), PINS_DIR)

    def test_required_inputs(self) -> None:
        root = scratch(self)
        _ = (root / "a.txt").write_text("a")
        cases = {
            "sign-object": {"SIGN_OBJECT": " "},
            "sigul-key-name": {"SIGUL_KEY_NAME": ""},
            "sigul-conf": {"HAVE_SIGUL_CONF": "false"},
            "sigul-pass": {"HAVE_SIGUL_PASS": "false"},
            "sigul-pki": {"HAVE_SIGUL_PKI": "false"},
        }
        for name, override in cases.items():
            with self.subTest(input=name):
                with self.assertRaises(InputError) as caught:
                    _ = build_plan(base_env(root, **override), PINS_DIR)
                self.assertIn(f"Input '{name}' is required", str(caught.exception))

    def test_unknown_sign_type(self) -> None:
        root = scratch(self)
        with self.assertRaises(InputError):
            _ = build_plan(base_env(root, SIGN_TYPE="sign-everything"), PINS_DIR)

    def test_gh_key_with_sign_data_is_noted_not_refused(self) -> None:
        root = scratch(self)
        _ = (root / "a.txt").write_text("a")
        plan = build_plan(base_env(root, HAVE_GH_KEY="true"), PINS_DIR)
        self.assertIn("gh-key is not used for sign-data", plan.messages.notices)

    def test_git_tag(self) -> None:
        root = make_repository(scratch(self) / "repo", tag="v1.0.0")
        env = base_env(root, SIGN_TYPE="sign-git-tag", SIGN_OBJECT=" v1.0.0\n")
        with self.assertRaises(InputError) as caught:
            _ = build_plan(env, PINS_DIR)
        self.assertIn("gh-key", str(caught.exception))
        plan = build_plan(dict(env, HAVE_GH_KEY="true"), PINS_DIR)
        self.assertEqual((plan.tag, plan.push_tag), ("v1.0.0", True))
        plan = build_plan(dict(env, PUSH_TAG="false"), PINS_DIR)
        self.assertFalse(plan.push_tag)

    def test_git_tag_rejections(self) -> None:
        root = make_repository(scratch(self) / "repo", tag="v1.0.0")
        env = base_env(root, SIGN_TYPE="sign-git-tag", HAVE_GH_KEY="true")
        for name in ("HEAD:refs/heads/main", "a..b", "two words", "line\nbreak"):
            with self.subTest(tag=name), self.assertRaises(ActionError):
                _ = build_plan(dict(env, SIGN_OBJECT=name), PINS_DIR)

    def test_git_tag_needs_a_standard_checkout(self) -> None:
        base = scratch(self)
        plain = base / "plain"
        plain.mkdir()
        worktree = base / "worktree"
        worktree.mkdir()
        _ = (worktree / ".git").write_text("gitdir: /elsewhere\n")
        linked = base / "linked"
        linked.mkdir()
        (linked / ".git").symlink_to(make_repository(base / "real") / ".git")
        # A standard-looking checkout whose object store alone is a link.
        borrowed = make_repository(base / "borrowed")
        elsewhere = base / "elsewhere-objects"
        _ = (borrowed / ".git" / "objects").rename(elsewhere)
        (borrowed / ".git" / "objects").symlink_to(elsewhere)
        for root, expected in (
            (plain, "no .git"),
            (worktree, "no .git"),
            (linked, "symlink"),
            (borrowed, "objects is not a directory inside .git"),
        ):
            env = base_env(
                root, SIGN_TYPE="sign-git-tag", SIGN_OBJECT="v1", HAVE_GH_KEY="true"
            )
            with self.subTest(root=root.name), self.assertRaises(ActionError) as caught:
                _ = build_plan(env, PINS_DIR)
            self.assertIn(expected, str(caught.exception))

    def test_gh_user_falls_back(self) -> None:
        root = scratch(self)
        _ = (root / "a.txt").write_text("a")
        plan = build_plan(base_env(root, GH_USER="", GITHUB_ACTOR="someone"), PINS_DIR)
        self.assertEqual(plan.gh_user, "someone")
        plan = build_plan(base_env(root, GH_USER=""), PINS_DIR)
        self.assertEqual(plan.gh_user, "x-access-token")


if __name__ == "__main__":
    _ = unittest.main()
