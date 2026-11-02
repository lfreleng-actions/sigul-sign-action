# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for sign-type check-connection on the runner.

The modules under test are imported inside each test, so that a test
written before its code fails as a test, not at collection.
"""

from __future__ import annotations

import importlib
import io
import os
import re
import shutil
import subprocess
import threading
import unittest
from collections.abc import Callable
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest import mock

from action_common import ActionError, InputError
from action_inputs import build_plan
from client_container import ContainerRun, PulledImage
from prepare_credentials import PreparedCredentials
from sigul_action import main

from tests.helpers import PINS_DIR, REPOSITORY, base_env, make_repository, scratch
from tests.test_cleanup_security import SigningFixture

# action.yaml's default exclude-globs, as the validation step receives it.
ACTION_EXCLUDES = (
    "*.asc\n*.md5\n*.sha1\n_maven.repositories\n_remote.repositories\n"
    + "*.lastUpdated\nmaven-metadata.xml\nmaven-metadata-local.xml\n"
)


def check_env(workspace: Path, **overrides: str) -> dict[str, str]:
    """The validation step's environment for a plain connection check."""
    env = base_env(
        workspace,
        SIGN_TYPE="check-connection",
        SIGN_OBJECT="",
        EXCLUDE_GLOBS=ACTION_EXCLUDES,
    )
    env.update(overrides)
    return env


def public_key_module() -> ModuleType:
    return importlib.import_module("public_key")


def fingerprints_from_colons(listing: str) -> list[str]:
    function = cast(
        Callable[[str], list[str]], public_key_module().fingerprints_from_colons
    )
    return function(listing)


def public_key_fingerprints(path: Path, home: Path) -> list[str]:
    function = cast(
        Callable[[Path, Path], list[str]], public_key_module().public_key_fingerprints
    )
    return function(path, home)


def make_public_key(case: unittest.TestCase, subkeys: int) -> tuple[bytes, list[str]]:
    """Generate a throwaway key and return its armoured public half and
    its fingerprints, primary first."""
    if shutil.which("gpg") is None:
        case.skipTest("gpg is not installed")
    home = scratch(case)
    home.chmod(0o700)
    env = {"PATH": "/usr/bin:/bin", "GNUPGHOME": str(home), "LC_ALL": "C"}
    case.addCleanup(
        subprocess.run,
        ["gpgconf", "--kill", "all"],
        env=env,
        capture_output=True,
        check=False,
    )
    batch = ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]

    def gpg(*args: str) -> str:
        done = subprocess.run(
            [*batch, *args], env=env, capture_output=True, text=True, check=True
        )
        return done.stdout

    _ = gpg(
        "--quick-gen-key", "Test <test@example.invalid>", "ed25519", "sign", "never"
    )
    listing = gpg("--with-colons", "--list-keys")
    primary = [
        line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
    ][0]
    for index in range(subkeys):
        algorithm, usage = (
            ("cv25519", "encr") if index % 2 == 0 else ("ed25519", "sign")
        )
        _ = gpg("--quick-add-key", primary, algorithm, usage, "never")
    listing = gpg("--with-colons", "--with-subkey-fingerprint", "--list-keys")
    fingerprints = [
        line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
    ]
    armoured = subprocess.run(
        ["gpg", "--batch", "--armor", "--export", primary],
        env=env,
        capture_output=True,
        check=True,
    ).stdout
    return armoured, fingerprints


class InputTests(unittest.TestCase):
    def test_check_connection_is_a_sign_type(self) -> None:
        root = scratch(self)
        plan = build_plan(check_env(root), PINS_DIR)
        self.assertEqual(plan.sign_type, "check-connection")
        self.assertEqual((plan.targets, plan.tag), ((), ""))
        self.assertEqual(plan.messages.notices, [])

    def test_unknown_sign_type_lists_all_three(self) -> None:
        root = scratch(self)
        with self.assertRaises(InputError) as caught:
            _ = build_plan(base_env(root, SIGN_TYPE="sign-everything"), PINS_DIR)
        for name in ("sign-data", "sign-git-tag", "check-connection"):
            self.assertIn(f"'{name}'", str(caught.exception))

    def test_sign_object_is_required_to_sign(self) -> None:
        root = make_repository(scratch(self) / "repo", tag="v1")
        for sign_type in ("sign-data", "sign-git-tag"):
            for blank in ("", " \n"):
                with self.subTest(sign_type=sign_type, blank=blank):
                    env = base_env(
                        root, SIGN_TYPE=sign_type, SIGN_OBJECT=blank, HAVE_GH_KEY="true"
                    )
                    with self.assertRaises(InputError) as caught:
                        _ = build_plan(env, PINS_DIR)
                    self.assertIn(
                        "Input 'sign-object' is required", str(caught.exception)
                    )

    def test_sign_object_is_refused_for_check_connection(self) -> None:
        root = scratch(self)
        _ = (root / "a.txt").write_text("a")
        for sign_object in ("a.txt", "v1.0.0", "\na.txt\n"):
            with self.subTest(sign_object=sign_object):
                with self.assertRaises(InputError) as caught:
                    _ = build_plan(check_env(root, SIGN_OBJECT=sign_object), PINS_DIR)
                self.assertIn("sign-object", str(caught.exception))
                self.assertIn("check-connection", str(caught.exception))

    def test_blank_sign_object_is_empty_for_check_connection(self) -> None:
        root = scratch(self)
        plan = build_plan(check_env(root, SIGN_OBJECT=" \n"), PINS_DIR)
        self.assertEqual(plan.targets, ())

    def test_dry_run_is_refused_for_check_connection(self) -> None:
        root = scratch(self)
        with self.assertRaises(InputError) as caught:
            _ = build_plan(check_env(root, DRY_RUN="true"), PINS_DIR)
        self.assertIn("dry-run", str(caught.exception))
        self.assertIn("check-connection", str(caught.exception))

    def test_dry_run_rejection_reports_validation_rejected(self) -> None:
        root = scratch(self)
        output = root / "validation-output"
        env = check_env(root, DRY_RUN="true", GITHUB_OUTPUT=str(output))
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sigul_action.check_runtime"),
            redirect_stdout(io.StringIO()),
        ):
            status = main(["validate"])
        self.assertEqual(status, 1)
        self.assertEqual(output.read_text(), "validation_status=rejected\n")

    def test_validation_passes_and_reports_the_check(self) -> None:
        root = scratch(self)
        output = root / "validation-output"
        env = check_env(root, GITHUB_OUTPUT=str(output), CONTAINER="modern")
        log = io.StringIO()
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sigul_action.check_runtime"),
            redirect_stdout(log),
        ):
            status = main(["validate"])
        self.assertEqual(status, 0, log.getvalue())
        self.assertEqual(output.read_text(), "validation_status=passed\n")
        self.assertIn("signs nothing", log.getvalue())

    def test_unused_inputs_are_noted_not_refused(self) -> None:
        root = scratch(self)
        cases = {
            "gh-key": {"HAVE_GH_KEY": "true"},
            "push-tag": {"PUSH_TAG": "false"},
            "exclude-globs": {"EXCLUDE_GLOBS": "*.zip\n"},
        }
        for name, override in cases.items():
            with self.subTest(input=name):
                plan = build_plan(check_env(root, **override), PINS_DIR)
                self.assertEqual(
                    plan.messages.notices, [f"{name} is not used for check-connection"]
                )

    def test_default_exclude_globs_are_not_noted(self) -> None:
        root = scratch(self)
        # Spacing and blank lines do not make the default a choice.
        spaced = "\n".join(f"  {line}  " for line in ACTION_EXCLUDES.splitlines())
        for raw in (ACTION_EXCLUDES, spaced + "\n\n"):
            with self.subTest(raw=raw):
                plan = build_plan(check_env(root, EXCLUDE_GLOBS=raw), PINS_DIR)
                self.assertEqual(plan.messages.notices, [])

    def test_default_exclude_globs_match_action_yaml(self) -> None:
        action_inputs = importlib.import_module("action_inputs")
        source = (REPOSITORY / "action.yaml").read_text()
        found = re.search(
            r"(?m)^  exclude-globs:\n(?:    .*\n)*?    default: \|\n((?:      .*\n)+)",
            source,
        )
        assert found is not None
        defaults = tuple(line.strip() for line in found[1].splitlines())
        excludes = cast(tuple[str, ...], action_inputs.DEFAULT_EXCLUDE_GLOBS)
        self.assertEqual(excludes, defaults)
        self.assertEqual(defaults, tuple(ACTION_EXCLUDES.split()))


class ActionMetadataTests(unittest.TestCase):
    def test_sign_object_is_optional_in_action_yaml(self) -> None:
        source = (REPOSITORY / "action.yaml").read_text()
        block = re.search(r"(?m)^  sign-object:\n((?:    .*\n)+)", source)
        assert block is not None
        self.assertIn("    required: false\n", block[1])

    def test_public_key_fingerprints_is_an_output_of_the_signing_step(self) -> None:
        source = (REPOSITORY / "action.yaml").read_text()
        found = re.search(
            r"(?m)^  public_key_fingerprints:\n(?:    .*\n)+?"
            + r"    value: \$\{\{ steps\.sign\.outputs\.public_key_fingerprints \}\}$",
            source,
        )
        self.assertIsNotNone(found, "action.yaml has no public_key_fingerprints output")


COLONS_TWO_SUBKEYS = """\
pub:-:255:22:CFEEFC7C5D05A708:1793458665:::-:::scESC:::::ed25519:::0:
fpr:::::::::0f28618e4d491c7ee16211dacfeefc7c5d05a708:
uid:-::::1793458665::230162C5BA27CB835FEFA182F7362D77F77BB1A7::Test::::::::::0:
sub:-:255:18:37C352C81EC96DBA:1793458665::::::e:::::cv25519::
fpr:::::::::02A209825B16E148B58AA1F237C352C81EC96DBA:
sub:-:255:22:88EAA97D419A13EE:1793458665::::::s:::::ed25519::
fpr:::::::::A9FFEBFBDF7C2C8BA867A1E088EAA97D419A13EE:
"""


class FingerprintTests(unittest.TestCase):
    def test_primary_then_every_subkey_in_upper_case(self) -> None:
        fingerprints = fingerprints_from_colons(COLONS_TWO_SUBKEYS)
        self.assertEqual(
            fingerprints,
            [
                "0F28618E4D491C7EE16211DACFEEFC7C5D05A708",
                "02A209825B16E148B58AA1F237C352C81EC96DBA",
                "A9FFEBFBDF7C2C8BA867A1E088EAA97D419A13EE",
            ],
        )

    def test_listings_that_are_not_one_public_key_are_refused(self) -> None:
        primary = COLONS_TWO_SUBKEYS.split("uid:")[0]
        cases = {
            "empty": "",
            "two keys": primary + primary,
            "a secret key": COLONS_TWO_SUBKEYS.replace("pub:", "sec:"),
            "a secret subkey": COLONS_TWO_SUBKEYS.replace("sub:", "ssb:", 1),
            "a subkey before the key": COLONS_TWO_SUBKEYS.split("uid:")[1].split(
                "\n", 1
            )[1]
            + primary,
            "a key without a fingerprint": COLONS_TWO_SUBKEYS.replace(
                "fpr:::::::::0f28618e4d491c7ee16211dacfeefc7c5d05a708:\n", ""
            ),
            "a subkey without a fingerprint": COLONS_TWO_SUBKEYS.rsplit("fpr:", 1)[0],
            "a malformed fingerprint": COLONS_TWO_SUBKEYS.replace(
                "02A209825B16E148B58AA1F237C352C81EC96DBA", "not-hex"
            ),
        }
        for name, listing in cases.items():
            with self.subTest(case=name), self.assertRaises(ActionError):
                _ = fingerprints_from_colons(listing)

    def test_gpg_lists_a_key_with_several_subkeys(self) -> None:
        armoured, expected = make_public_key(self, subkeys=2)
        self.assertEqual(len(expected), 3)
        root = scratch(self)
        reply = root / "public-key"
        _ = reply.write_bytes(armoured)
        home = root / "gnupg"
        home.mkdir(mode=0o700)
        found = public_key_fingerprints(reply, home)
        self.assertEqual(found, expected)

    def test_replies_that_are_not_one_armoured_public_key_are_refused(self) -> None:
        armoured, _ = make_public_key(self, subkeys=1)
        text = armoured.decode("ascii")
        signature = (
            "-----BEGIN PGP SIGNATURE-----\n\nabc=\n-----END PGP SIGNATURE-----\n"
        )
        cases = {
            "empty": b"",
            "plain text": b"ERROR: Authentication failed\n",
            "a signature": signature.encode(),
            "two key blocks": (text + text).encode(),
            "a key and a signature": (text + signature).encode(),
            "text before the key": ("Key follows\n" + text).encode(),
            "not ASCII": armoured.replace(b"\n\n", b"\n\xff\n", 1),
            "a corrupt key": armoured[:200] + b"\n" + armoured[-40:],
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                root = scratch(self)
                reply = root / "public-key"
                _ = reply.write_bytes(data)
                home = root / "gnupg"
                home.mkdir(mode=0o700)
                with self.assertRaises(ActionError):
                    _ = public_key_fingerprints(reply, home)

    def test_a_link_is_not_followed(self) -> None:
        armoured, _ = make_public_key(self, subkeys=0)
        root = scratch(self)
        target = root / "elsewhere"
        _ = target.write_bytes(armoured)
        reply = root / "public-key"
        reply.symlink_to(target)
        home = root / "gnupg"
        home.mkdir(mode=0o700)
        with self.assertRaises(ActionError):
            _ = public_key_fingerprints(reply, home)

    def test_a_missing_reply_is_refused(self) -> None:
        root = scratch(self)
        home = root / "gnupg"
        home.mkdir(mode=0o700)
        with self.assertRaises(ActionError):
            _ = public_key_fingerprints(root / "absent", home)

    def test_a_fifo_is_refused_without_waiting_for_a_writer(self) -> None:
        # Opening a FIFO to read blocks until a writer appears, outside
        # every timeout the action sets, so a container leaving one in
        # place of the reply would hang the step. The check runs in a
        # thread here, so that a regression fails rather than hangs.
        root = scratch(self)
        reply = root / "public-key"
        os.mkfifo(reply, 0o600)
        home = root / "gnupg"
        home.mkdir(mode=0o700)
        refused: list[ActionError] = []

        def check() -> None:
            try:
                _ = public_key_fingerprints(reply, home)
            except ActionError as error:
                refused.append(error)

        worker = threading.Thread(target=check, daemon=True)
        worker.start()
        worker.join(timeout=5)
        waited = worker.is_alive()
        if waited:
            # Release the blocked open, so the thread can finish.
            os.close(os.open(reply, os.O_WRONLY | os.O_NONBLOCK))
            worker.join(timeout=5)
        self.assertFalse(waited, "reading the reply waited for a FIFO writer")
        self.assertEqual(len(refused), 1)


class ConnectionFixture:
    """A connection check's container run, stopped at the Docker launch."""

    def __init__(self, case: unittest.TestCase) -> None:
        root = scratch(case)
        self.workspace: Path = root / "workspace"
        self.workspace.mkdir()
        self.creds: Path = root / "creds"
        self.creds.mkdir()
        # Absent, as sign() leaves it once the bundle is decrypted.
        self.gnupg: Path = root / "gnupg"
        self.output: Path = root / "github-output"
        plan = build_plan(check_env(self.workspace, CONTAINER="modern"), PINS_DIR)
        prepared = PreparedCredentials(
            root / "client.conf", "/sigul-creds/pki", "/nss", True
        )
        pulled = PulledImage("fixture:1", "fixture:1", "root", "linux/amd64")
        self.run: ContainerRun = ContainerRun(
            plan, pulled, prepared, self.creds, "check-fixture", "1000:1000"
        )

    def check(
        self, reply: bytes | None, status: int = 0
    ) -> tuple[list[str], dict[str, str]]:
        """Run the check with a container that leaves reply and exits status;
        return the container's argv and the step outputs."""
        check_connection = cast(
            Callable[[ContainerRun, Path], None],
            public_key_module().check_connection,
        )

        def container(_argv: list[str], _name: str, _timeout: int | None) -> int:
            if reply is not None:
                _ = (self.creds / "public-key").write_bytes(reply)
            return status

        with (
            mock.patch.dict(
                os.environ,
                {"GITHUB_OUTPUT": str(self.output), "PATH": "/usr/bin:/bin"},
                clear=True,
            ),
            mock.patch("public_key.run_container", side_effect=container) as start,
            redirect_stdout(io.StringIO()),
        ):
            try:
                check_connection(self.run, self.gnupg)
            finally:
                outputs = (
                    dict(
                        line.split("=", 1)
                        for line in self.output.read_text().splitlines()
                    )
                    if self.output.exists()
                    else {}
                )
        start.assert_called_once()
        return cast(list[str], start.call_args.args[0]), outputs


class ConnectionRunTests(unittest.TestCase):
    """public_key.check_connection, stopped at the Docker launch."""

    def test_success_reports_the_fingerprints_and_signs_nothing(self) -> None:
        armoured, fingerprints = make_public_key(self, subkeys=2)
        fixture = ConnectionFixture(self)
        argv, outputs = fixture.check(armoured)
        self.assertEqual(
            outputs,
            {"signed_count": "0", "public_key_fingerprints": " ".join(fingerprints)},
        )
        self.assertEqual(argv[-1], "/sigul-scripts/get_public_key.py")
        env = dict(
            argv[index + 1].split("=", 1)
            for index, arg in enumerate(argv)
            if arg == "--env"
        )
        self.assertEqual(env["PUBLIC_KEY_FILE"], "/sigul-creds/public-key")
        # The container caps the reply at the size the runner accepts.
        self.assertEqual(env["PUBLIC_KEY_LIMIT"], str(1024 * 1024))
        self.assertNotIn("MODE", env)
        self.assertNotIn("MANIFEST", env)
        self.assertNotIn("--password", argv)
        workspace = os.path.realpath(fixture.workspace)
        mounts = [argv[index + 1] for index, arg in enumerate(argv) if arg == "--mount"]
        self.assertIn(
            f"type=bind,source={workspace},target={workspace},readonly", mounts
        )

    def test_container_failure_fails_the_step(self) -> None:
        armoured, _ = make_public_key(self, subkeys=0)
        fixture = ConnectionFixture(self)
        with self.assertRaises(ActionError):
            _ = fixture.check(armoured, status=1)
        self.assertFalse(fixture.output.exists())

    def test_a_reply_that_is_not_a_public_key_fails_the_step(self) -> None:
        for reply in (None, b"", b"not a key\n"):
            with self.subTest(reply=reply):
                fixture = ConnectionFixture(self)
                with self.assertRaises(ActionError):
                    _ = fixture.check(reply)
                self.assertFalse(fixture.output.exists())


class DispatchTests(unittest.TestCase):
    def test_sign_runs_the_connection_check_and_nothing_else(self) -> None:
        fixture = SigningFixture(self)
        fixture.plan = build_plan(check_env(fixture.base, CONTAINER="modern"), PINS_DIR)
        checked: list[Path] = []

        def check_connection(_run: ContainerRun, gnupg: Path) -> None:
            checked.append(gnupg)

        with ExitStack() as stack:
            fixture.isolate(stack)
            check = stack.enter_context(
                mock.patch(
                    "signing.check_connection",
                    create=True,
                    side_effect=check_connection,
                )
            )
            sign_git_tag = stack.enter_context(mock.patch("signing.sign_git_tag"))
            fixture.run()
        check.assert_called_once()
        sign_git_tag.assert_not_called()
        self.assertEqual(checked, [fixture.gnupg])
        self.assertFalse(fixture.work.exists())


if __name__ == "__main__":
    _ = unittest.main()
