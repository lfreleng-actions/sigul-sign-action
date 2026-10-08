# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Credential boundary regressions using private, synthetic fixtures only."""

from __future__ import annotations

import base64
import configparser
import io
import shutil
import subprocess
import tarfile
import traceback
import unittest
from collections.abc import Iterable
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from action_common import ActionError, minimal_env, system_tool
from gpg_bundle import UnprotectedBundleError, decrypt_bundle, kill_gpg_agent
from prepare_credentials import (
    PreparedCredentials,
    extract_bundle,
    prepare,
    rewrite_nss_dir,
)

from tests.helpers import scratch

CONFIG = "[client]\nbridge-hostname: bridge.example.org\n[nss]\nnss-password: x\n"
PASSWORD = "synthetic-bundle-passphrase"
NSS_PASSWORD = "synthetic-nss-password-not-for-logging"
CONTAINER_NSS = "/sigul-creds/pki/sigul"

# The proposed credential archive budget, tested through the public extractor.
# Repeated zero-filled payloads compress cheaply; no exhaustion probe is needed.
FILE_BYTES = 16 * 1024 * 1024
TOTAL_BYTES = 32 * 1024 * 1024
MEMBERS = 256
PATH_COMPONENTS = 16

ArchiveEntry = tuple[tarfile.TarInfo, bytes]


def entry(
    name: str,
    data: bytes = b"",
    *,
    kind: bytes = tarfile.REGTYPE,
    target: str = "",
    mode: int = 0o600,
) -> ArchiveEntry:
    """Describe an archive member without creating links on the host."""
    member = tarfile.TarInfo(name)
    member.type = kind
    member.linkname = target
    member.mode = mode
    member.size = len(data)
    return member, data


def pack(case: unittest.TestCase, entries: Iterable[ArchiveEntry]) -> Path:
    """Write a bounded compressed tar in a private temporary directory."""
    archive = scratch(case) / "pki.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for member, data in entries:
            tar.addfile(member, io.BytesIO(data))
    return archive


def prepare_tar(base: Path, archive: Path, config: str = CONFIG) -> PreparedCredentials:
    """Exercise preparation after decryption; crypto has separate real-GPG tests."""

    def copy_plaintext(
        _encrypted: Path, _passphrase: Path, output: Path, _home: Path
    ) -> None:
        _ = shutil.copyfile(archive, output)

    with mock.patch("prepare_credentials.decrypt_bundle", new=copy_plaintext):
        return prepare(
            base / "creds",
            base / "gnupg",
            "/sigul-creds",
            config,
            PASSWORD,
            "synthetic-ciphertext",
        )


class ArchiveLinkTests(unittest.TestCase):
    def test_regular_files_and_directories_are_accepted(self) -> None:
        archive = pack(
            self,
            [
                entry("sigul", kind=tarfile.DIRTYPE, mode=0o700),
                entry("sigul/key4.db", b"synthetic key material"),
            ],
        )
        destination = scratch(self) / "pki"
        extract_bundle(archive, destination)
        self.assertEqual(
            (destination / "sigul/key4.db").read_bytes(), b"synthetic key material"
        )

    @unittest.expectedFailure
    def test_in_tree_file_symlink_is_rejected(self) -> None:
        archive = pack(
            self,
            [
                entry("sigul/key4.db", b"synthetic key material"),
                entry("sigul/alias", kind=tarfile.SYMTYPE, target="key4.db"),
            ],
        )
        with self.assertRaises(ActionError):
            extract_bundle(archive, scratch(self) / "pki")

    @unittest.expectedFailure
    def test_in_tree_directory_symlink_is_rejected(self) -> None:
        archive = pack(
            self,
            [
                entry("sigul", kind=tarfile.DIRTYPE, mode=0o700),
                entry("alias", kind=tarfile.SYMTYPE, target="sigul"),
            ],
        )
        with self.assertRaises(ActionError):
            extract_bundle(archive, scratch(self) / "pki")

    @unittest.expectedFailure
    def test_in_tree_hardlink_is_rejected(self) -> None:
        archive = pack(
            self,
            [
                entry("sigul/key4.db", b"synthetic key material"),
                entry("alias", kind=tarfile.LNKTYPE, target="sigul/key4.db"),
            ],
        )
        with self.assertRaises(ActionError):
            extract_bundle(archive, scratch(self) / "pki")

    @unittest.expectedFailure
    def test_relocated_link_cannot_rewrite_an_external_configuration(self) -> None:
        base = scratch(self)
        work = base / "work"
        work.mkdir(mode=0o700)
        outside = base / "outside-work"
        outside.mkdir(mode=0o700)
        victim = outside / "client.conf"
        original = f"[nss]\nnss-dir: /outside-original\nnss-password: {NSS_PASSWORD}\n"
        _ = victim.write_text(original)
        members = [
            entry(name, kind=tarfile.DIRTYPE, mode=0o700)
            for name in ("a", "a/b", "a/b/c", "sigul")
        ]
        # CVE-2025-4138: the dangling source resolves inside pki, but the
        # hardlink fallback relocates its unfiltered target outside work.
        members += [
            entry("a/b/c/anchor", kind=tarfile.SYMTYPE, target="../../../outside-work"),
            entry(".sigul", kind=tarfile.LNKTYPE, target="a/b/c/anchor", mode=0o700),
            entry("sigul/cert9.db"),
            entry("sigul/key4.db"),
        ]
        archive = pack(self, members)
        with self.assertRaises(ActionError):
            _ = prepare_tar(work, archive)
        self.assertEqual(victim.read_text(), original)
        # Patched tarfile rejects the relocated link, but still admits
        # the first symlink. The credential policy must admit neither.
        self.assertFalse((work / "creds/pki/a/b/c/anchor").is_symlink())

    def test_parent_traversal_is_rejected(self) -> None:
        base = scratch(self)
        outside = base / "outside"
        _ = outside.write_bytes(b"untouched")
        archive = pack(self, [entry("../outside", b"replacement")])
        with self.assertRaises(ActionError):
            extract_bundle(archive, base / "pki")
        self.assertEqual(outside.read_bytes(), b"untouched")

    def test_special_files_are_rejected(self) -> None:
        for kind in (tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                archive = pack(self, [entry("special", kind=kind)])
                with self.assertRaises(ActionError):
                    extract_bundle(archive, scratch(self) / "pki")


class ArchiveBudgetTests(unittest.TestCase):
    @unittest.expectedFailure
    def test_single_file_over_budget_is_rejected(self) -> None:
        archive = pack(self, [entry("key4.db", bytes(FILE_BYTES + 1))])
        with self.assertRaises(ActionError):
            extract_bundle(archive, scratch(self) / "pki")

    @unittest.expectedFailure
    def test_total_expansion_over_budget_is_rejected(self) -> None:
        payload = bytes(FILE_BYTES)
        archive = pack(
            self,
            [
                entry("first.db", payload),
                entry("second.db", payload),
                entry("extra", b"x"),
            ],
        )
        with self.assertRaises(ActionError):
            extract_bundle(archive, scratch(self) / "pki")

    def test_files_at_both_byte_limits_are_accepted(self) -> None:
        payload = bytes(FILE_BYTES)
        archive = pack(self, [entry("first.db", payload), entry("second.db", payload)])
        destination = scratch(self) / "pki"
        extract_bundle(archive, destination)
        sizes = [
            (destination / name).stat().st_size for name in ("first.db", "second.db")
        ]
        self.assertEqual(sizes, [FILE_BYTES, FILE_BYTES])
        self.assertEqual(sum(sizes), TOTAL_BYTES)

    @unittest.expectedFailure
    def test_too_many_members_including_directories_are_rejected(self) -> None:
        archive = pack(
            self,
            (
                entry(f"directory-{i}", kind=tarfile.DIRTYPE, mode=0o700)
                for i in range(MEMBERS + 1)
            ),
        )
        with self.assertRaises(ActionError):
            extract_bundle(archive, scratch(self) / "pki")

    def test_member_count_at_limit_is_accepted(self) -> None:
        archive = pack(self, (entry(f"file-{i}") for i in range(MEMBERS)))
        destination = scratch(self) / "pki"
        extract_bundle(archive, destination)
        self.assertEqual(len(list(destination.iterdir())), MEMBERS)

    @unittest.expectedFailure
    def test_path_deeper_than_limit_is_rejected(self) -> None:
        name = "/".join(["directory"] * PATH_COMPONENTS + ["key4.db"])
        archive = pack(self, [entry(name)])
        with self.assertRaises(ActionError):
            extract_bundle(archive, scratch(self) / "pki")

    def test_path_at_depth_limit_is_accepted(self) -> None:
        name = "/".join(["directory"] * (PATH_COMPONENTS - 1) + ["key4.db"])
        archive = pack(self, [entry(name)])
        destination = scratch(self) / "pki"
        extract_bundle(archive, destination)
        self.assertTrue((destination / name).is_file())


class ConfigurationSecurityTests(unittest.TestCase):
    @unittest.expectedFailure
    def test_indented_nss_options_remain_separate(self) -> None:
        text = f"[nss]\n  nss-dir: /old\n  nss-password: {NSS_PASSWORD}\n"
        parser = configparser.RawConfigParser()
        parser.read_string(rewrite_nss_dir(text, CONTAINER_NSS, True))
        self.assertEqual(parser.get("nss", "nss-dir"), CONTAINER_NSS)
        self.assertEqual(parser.get("nss", "nss-password"), NSS_PASSWORD)

    @unittest.expectedFailure
    def test_adding_nss_dir_preserves_an_indented_password(self) -> None:
        text = f"[nss]\n  nss-password: {NSS_PASSWORD}\n"
        parser = configparser.RawConfigParser()
        parser.read_string(rewrite_nss_dir(text, CONTAINER_NSS, True))
        self.assertEqual(parser.get("nss", "nss-dir"), CONTAINER_NSS)
        self.assertEqual(parser.get("nss", "nss-password"), NSS_PASSWORD)

    @unittest.expectedFailure
    def test_continued_nss_dir_is_replaced_as_one_value(self) -> None:
        text = f"[nss]\nnss-dir:\n  /old/location\nnss-password: {NSS_PASSWORD}\n"
        parser = configparser.RawConfigParser()
        parser.read_string(rewrite_nss_dir(text, CONTAINER_NSS, True))
        self.assertEqual(parser.get("nss", "nss-dir"), CONTAINER_NSS)
        self.assertEqual(parser.get("nss", "nss-password"), NSS_PASSWORD)

    @unittest.expectedFailure
    def test_option_like_password_continuation_is_preserved(self) -> None:
        text = (
            f"[nss]\nnss-dir: /old\nnss-password: {NSS_PASSWORD}\n"
            "  nss-dir: literal-password-continuation\n"
        )
        parser = configparser.RawConfigParser()
        parser.read_string(rewrite_nss_dir(text, CONTAINER_NSS, True))
        self.assertEqual(parser.get("nss", "nss-dir"), CONTAINER_NSS)
        self.assertEqual(
            parser.get("nss", "nss-password"),
            NSS_PASSWORD + "\nnss-dir: literal-password-continuation",
        )

    def test_percent_characters_remain_literal(self) -> None:
        password = "synthetic%password%(not-interpolated)s"
        text = f"[nss]\nnss-dir: /old\nnss-password: {password}\n"
        parser = configparser.RawConfigParser()
        parser.read_string(rewrite_nss_dir(text, CONTAINER_NSS, True))
        self.assertEqual(parser.get("nss", "nss-password"), password)

    @unittest.expectedFailure
    def test_malformed_configuration_has_no_value_bearing_exception(self) -> None:
        text = f"[nss]\nnss-password: {NSS_PASSWORD}\n{NSS_PASSWORD}\n"
        with self.assertRaises(ActionError) as caught:
            _ = rewrite_nss_dir(text, CONTAINER_NSS, True)
        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertNotIn(NSS_PASSWORD, rendered)

    @unittest.expectedFailure
    def test_container_path_cannot_inject_an_option(self) -> None:
        with self.assertRaises(ActionError):
            _ = rewrite_nss_dir(
                "[nss]\nnss-dir: /old\n",
                CONTAINER_NSS + "\nextra-option: injected",
                True,
            )

    @unittest.expectedFailure
    def test_prepare_preserves_the_bundled_indented_password(self) -> None:
        user = f"[nss]\n  nss-dir: /old\n  nss-password: {NSS_PASSWORD}\n"
        archive = pack(
            self,
            [
                entry("sigul/cert9.db"),
                entry("sigul/key4.db"),
                entry(".sigul/client.conf", user.encode()),
            ],
        )
        base = scratch(self)
        output = io.StringIO()
        with redirect_stdout(output):
            prepared = prepare_tar(base, archive)
        parser = configparser.RawConfigParser()
        _ = parser.read([prepared.system_config, base / "creds/pki/.sigul/client.conf"])
        self.assertTrue(prepared.layered)
        self.assertEqual(parser.get("nss", "nss-dir"), CONTAINER_NSS)
        self.assertEqual(parser.get("nss", "nss-password"), NSS_PASSWORD)
        self.assertNotIn(NSS_PASSWORD, output.getvalue())

    @unittest.expectedFailure
    def test_prepare_refuses_malformed_bundled_config_without_its_value(self) -> None:
        user = f"[nss]\nnss-password: {NSS_PASSWORD}\n{NSS_PASSWORD}\n"
        archive = pack(
            self,
            [
                entry("sigul/cert9.db"),
                entry("sigul/key4.db"),
                entry(".sigul/client.conf", user.encode()),
            ],
        )
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(ActionError) as caught:
            _ = prepare_tar(scratch(self), archive)
        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertNotIn(NSS_PASSWORD, rendered + output.getvalue())


class GPGStatusTests(unittest.TestCase):
    def paths(self) -> tuple[Path, Path, Path, Path]:
        """Return private synthetic GPG inputs and an existing plaintext output."""
        home = scratch(self)
        encrypted, password, output = (
            home / name for name in ("pki.gpg", "passphrase", "pki.tar")
        )
        for path, data in (
            (encrypted, b"synthetic ciphertext"),
            (password, PASSWORD.encode()),
            (output, b"synthetic plaintext"),
        ):
            path.touch(mode=0o600)
            _ = path.write_bytes(data)
        return encrypted, password, output, home

    @unittest.expectedFailure
    def test_zero_exit_without_mdc_is_still_rejected(self) -> None:
        status = (
            "[GNUPG:] BEGIN_DECRYPTION\n"
            "[GNUPG:] DECRYPTION_INFO 0 3 0\n"
            "[GNUPG:] DECRYPTION_OKAY\n"
            "[GNUPG:] END_DECRYPTION\n"
        )
        done = subprocess.CompletedProcess(
            ["gpg"],
            0,
            stdout=status,
            stderr="gpg: WARNING: message was not integrity protected\n",
        )
        with mock.patch("gpg_bundle.subprocess.run", return_value=done):
            with self.assertRaises(UnprotectedBundleError):
                decrypt_bundle(*self.paths())

    @unittest.expectedFailure
    def test_gpg_diagnostic_values_are_not_exposed(self) -> None:
        done = subprocess.CompletedProcess(
            ["gpg"], 2, stdout="", stderr=f"gpg: malformed data: {NSS_PASSWORD}\n"
        )
        with mock.patch("gpg_bundle.subprocess.run", return_value=done):
            with self.assertRaises(ActionError) as caught:
                decrypt_bundle(*self.paths())
        self.assertNotIn(
            NSS_PASSWORD, "".join(traceback.format_exception(caught.exception))
        )

    @unittest.expectedFailure
    def test_gpg_wait_is_bounded_and_timeout_is_sanitized(self) -> None:
        def never_finishes(
            argv: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            timeout = kwargs.get("timeout")
            if not isinstance(timeout, (int, float)):
                self.fail("GPG was started without a finite timeout")
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 60)
            raise subprocess.TimeoutExpired(argv, timeout, stderr=NSS_PASSWORD)

        with mock.patch("gpg_bundle.subprocess.run", side_effect=never_finishes):
            with self.assertRaises(ActionError) as caught:
                decrypt_bundle(*self.paths())
        self.assertNotIn(
            NSS_PASSWORD, "".join(traceback.format_exception(caught.exception))
        )


class GPGEnvelopeTests(unittest.TestCase):
    def envelope(self, *, encrypted: bool) -> bytes:
        """Wrap a synthetic NSS archive with real GPG, never a user keyring."""
        gpg = system_tool("gpg")
        if gpg is None:
            self.skipTest("gpg is not installed in the action's system path")
        archive = pack(self, [entry("sigul/cert9.db"), entry("sigul/key4.db")])
        home = scratch(self)
        self.addCleanup(kill_gpg_agent, home)
        password = home / "passphrase"
        password.touch(mode=0o600)
        _ = password.write_text(PASSWORD + "\n")
        output = home / "pki.gpg"
        argv = [
            gpg,
            "--homedir",
            str(home),
            "--batch",
            "--yes",
            "--quiet",
            "--output",
            str(output),
        ]
        if encrypted:
            argv += [
                "--pinentry-mode",
                "loopback",
                "--passphrase-file",
                str(password),
                "--cipher-algo",
                "AES256",
                "--symmetric",
            ]
        else:
            argv += ["--store"]
        _ = subprocess.run(
            [*argv, str(archive)],
            env=minimal_env({"HOME": str(home)}),
            capture_output=True,
            check=True,
            timeout=15,
        )
        return output.read_bytes()

    def materialize(self, packet: bytes) -> PreparedCredentials:
        """Prepare a real GPG packet using only the synthetic passphrase."""
        base = scratch(self)
        home = base / "gnupg"
        self.addCleanup(kill_gpg_agent, home)
        return prepare(
            base / "creds",
            home,
            "/sigul-creds",
            CONFIG,
            PASSWORD,
            base64.b64encode(packet).decode(),
        )

    @unittest.expectedFailure
    def test_unencrypted_store_packet_is_rejected(self) -> None:
        packet = self.envelope(encrypted=False)
        with self.assertRaises(ActionError):
            _ = self.materialize(packet)

    def test_authenticated_encrypted_packet_is_accepted(self) -> None:
        prepared = self.materialize(self.envelope(encrypted=True))
        self.assertEqual(prepared.container_nss_dir, CONTAINER_NSS)
        self.assertTrue((prepared.system_config.parent / "pki/sigul/key4.db").is_file())

    def test_modified_ciphertext_is_rejected(self) -> None:
        packet = bytearray(self.envelope(encrypted=True))
        packet[-1] ^= 1
        with self.assertRaises(ActionError):
            _ = self.materialize(bytes(packet))


if __name__ == "__main__":
    _ = unittest.main()
