# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/prepare_credentials.py."""

from __future__ import annotations

import base64
import io
import os
import re
import shutil
import subprocess
import tarfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from action_common import ActionError
from gpg_bundle import UnprotectedBundleError, kill_gpg_agent
from prepare_credentials import (
    check_configuration,
    decode_pki,
    first_line,
    prepare,
    rewrite_nss_dir,
)

from tests.helpers import scratch

PASSPHRASE = "bundle-passphrase"
HEAD = "[client]\nbridge-hostname: bridge.example.org\nbridge-port: 44334\n"
ONAP_NSS = "\n[nss]\nnss-dir: /home/jenkins/sigul\nnss-password: x\n"
HAVE_GPG = shutil.which("gpg") is not None

# A bundle as GnuPG 2.0 and earlier made one by default, and as the
# legacy action's CentOS 7 container (GnuPG 2.0.22) accepted: CAST5,
# with no modification detection code. A tar.xz of sigul/cert8.db and
# sigul/key3.db, encrypted with PASSPHRASE by
#   gpg1 --cipher-algo CAST5 --disable-mdc --symmetric --armor
# which GnuPG 2.2.8 and later refuse to decrypt without
# --ignore-mdc-error. 'gpg --list-packets' shows a plain 'encrypted
# data packet' rather than an integrity-protected one.
NO_MDC_BUNDLE = """\
-----BEGIN PGP MESSAGE-----

jA0EAwMClktGgoIXIpVgycAnpfTMcbkuqk6rUcVx+V3sApAImt8SpJnCZD7Au+iO
tWQ6Su/5XIGs3ODcba/J/psGCctyYJ+khMst/uNvLDVDYE22dZ+HvIEpJIL3NRt6
2LMdwqe27lifPYBmZxrucJMEF7i1tJWx+ex8vtsRt40EgalNuz0zWqSKBsS0IahW
RB4S6P+1rnhPtaao4e2Mq/53u8MrSmGc/7p3Egb2L0gztZH1fjzavKdzuhKNHiPn
5xQGrQEov1nYvsaFLvsrLnloIxpwYMCL/Bf2+Bn2fQdpDjzzC9Mmy6V1lmhW01rP
zqSiu3ExJRTO
=EKwW
-----END PGP MESSAGE-----
"""


def gpg_version() -> tuple[int, ...]:
    """Return the installed gpg's version, or () without one."""
    if not HAVE_GPG:
        return ()
    done = subprocess.run(
        ["gpg", "--version"], capture_output=True, text=True, check=False
    )
    first = (done.stdout.splitlines() or [""])[0]
    found = re.search(r"(\d+)\.(\d+)\.(\d+)", first)
    return tuple(int(part) for part in found.groups()) if found else ()


def build_bundle(
    case: unittest.TestCase,
    layout: str,
    extra: dict[str, str] | None = None,
    passphrase: str = PASSPHRASE,
    armour: bool = True,
    nss: bool = True,
    links: dict[str, str] | None = None,
) -> str:
    """Return an encrypted PKI bundle, as sigul-pki carries it. 'links'
    maps a path in the bundle to the relative target of a symlink."""
    base = scratch(case)
    tree = base / "tree"
    database = tree / layout if layout else tree
    database.mkdir(parents=True)
    if nss:
        for name in ("cert9.db", "key4.db"):
            _ = (database / name).write_bytes(b"")
    for name, body in (extra or {}).items():
        path = tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_text(body)
    for name, target in (links or {}).items():
        path = tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
    archive = base / "pki.tar.xz"
    with tarfile.open(archive, "w:xz") as tar:
        for child in sorted(tree.iterdir()):
            tar.add(child, arcname=child.name)
    home = base / "gpg"
    home.mkdir(mode=0o700)
    encrypted = base / "pki.gpg"
    argv = [
        "gpg",
        "--homedir",
        str(home),
        "--batch",
        "--yes",
        "--quiet",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        passphrase,
        "--symmetric",
        "--output",
        str(encrypted),
    ]
    if armour:
        argv.append("--armor")
    _ = subprocess.run([*argv, str(archive)], check=True, capture_output=True)
    kill_gpg_agent(home)
    if armour:
        return encrypted.read_text()
    return base64.b64encode(encrypted.read_bytes()).decode()


class PureFunctionTests(unittest.TestCase):
    def test_first_line(self) -> None:
        self.assertEqual(first_line("secret"), "secret")
        self.assertEqual(first_line("secret\n"), "secret")
        self.assertEqual(first_line("secret\nrest"), "secret")

    def test_jenkins_placeholders_are_refused(self) -> None:
        check_configuration(HEAD)
        for token in ("$SIGUL_CONFIG_USR", "$SIGUL_CONFIG_PSW"):
            with self.assertRaises(ActionError) as caught:
                check_configuration(HEAD + f"user-name: {token}\n")
            self.assertIn("sigul-config-credentials", str(caught.exception))

    def test_decode_pki(self) -> None:
        armoured = "-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----\n"
        self.assertEqual(decode_pki(armoured), armoured.encode())
        self.assertEqual(
            decode_pki(base64.b64encode(b"\x8c\x0d binary").decode()),
            b"\x8c\x0d binary",
        )
        self.assertEqual(decode_pki("not base64!"), b"not base64!")

    def test_rewrite_nss_dir(self) -> None:
        new = "nss-dir: /sigul-creds/pki/sigul"
        self.assertIn(
            new, rewrite_nss_dir(HEAD + ONAP_NSS, "/sigul-creds/pki/sigul", True)
        )
        duplicate = rewrite_nss_dir(
            "[nss]\nnss-dir: /a\nnss-dir = /b\nx: 1\n", "/n", True
        )
        self.assertEqual(duplicate, "[nss]\nnss-dir: /n\nx: 1\n")
        self.assertEqual(
            rewrite_nss_dir("[nss]\nx: 1\n", "/n", True), "[nss]\nnss-dir: /n\nx: 1\n"
        )
        self.assertEqual(
            rewrite_nss_dir(HEAD, "/n", True), HEAD + "\n[nss]\nnss-dir: /n\n"
        )
        self.assertEqual(rewrite_nss_dir("[nss]\nx: 1\n", "/n", False), "[nss]\nx: 1\n")
        # Option names are case-insensitive, as ConfigParser reads them;
        # a mixed-case entry is replaced, not shadowed by a second one.
        self.assertEqual(
            rewrite_nss_dir("[nss]\nNSS-Dir = /home/jenkins/sigul\n", "/n", True),
            "[nss]\nnss-dir: /n\n",
        )
        # Only [nss]'s nss-dir is Sigul's: one in another section stays
        # as written, and the real one is the one rewritten.
        self.assertEqual(
            rewrite_nss_dir(
                "[client]\nnss-dir: /ignored\n[nss]\nnss-dir: /old\n", "/n", True
            ),
            "[client]\nnss-dir: /ignored\n[nss]\nnss-dir: /n\n",
        )
        self.assertEqual(
            rewrite_nss_dir("[client]\nnss-dir: /ignored\n[nss]\nx: 1\n", "/n", True),
            "[client]\nnss-dir: /ignored\n[nss]\nnss-dir: /n\nx: 1\n",
        )
        self.assertEqual(rewrite_nss_dir("[nss]", "/n", True), "[nss]\nnss-dir: /n\n")


@unittest.skipUnless(HAVE_GPG, "gpg is not installed")
class PrepareTests(unittest.TestCase):
    def prepare(self, config: str, password: str, pki: str) -> tuple[Path, str]:
        base = scratch(self)
        creds = base / "creds"
        gnupg = base / "gnupg"
        try:
            prepared = prepare(creds, gnupg, "/sigul-creds", config, password, pki)
        finally:
            kill_gpg_agent(gnupg)
        self.assertEqual(prepared.system_config, creds / "client.conf")
        self.assertEqual(prepared.container_home, "/sigul-creds/pki")
        return creds, prepared.container_nss_dir

    def nss_dirs(self, text: str) -> list[str]:
        return [
            line.split(":", 1)[1].strip()
            for line in text.splitlines()
            if line.startswith("nss-dir")
        ]

    def test_bundle_layouts(self) -> None:
        cases = [
            ("sigul", True, "/sigul-creds/pki/sigul"),
            ("sigul", False, "/sigul-creds/pki/sigul"),
            (".sigul", True, "/sigul-creds/pki/.sigul"),
            ("", True, "/sigul-creds/pki"),
        ]
        for layout, armour, expected in cases:
            with self.subTest(layout=layout, armour=armour):
                creds, nss_dir = self.prepare(
                    HEAD + ONAP_NSS,
                    PASSPHRASE,
                    build_bundle(self, layout, armour=armour),
                )
                self.assertEqual(nss_dir, expected)
                config = (creds / "client.conf").read_text()
                self.assertEqual(self.nss_dirs(config), [expected])
                self.assertIn("bridge.example.org", config)

    def test_passphrase_file_holds_the_first_line(self) -> None:
        # A secret stored with a trailing newline, or extra lines, still
        # decrypts a bundle encrypted with its first line, and sigul is
        # sent exactly that line.
        creds, _ = self.prepare(
            HEAD, PASSPHRASE + "\nsecond line", build_bundle(self, "sigul")
        )
        self.assertEqual(
            (creds / "password").read_bytes(), PASSPHRASE.encode() + b"\0\n"
        )
        self.assertEqual((creds / "password").stat().st_mode & 0o777, 0o600)

    def test_multi_line_passphrase_bundle_gets_a_specific_error(self) -> None:
        pki = build_bundle(self, "sigul", passphrase=PASSPHRASE + "\nsecond line")
        with self.assertRaises(ActionError) as caught:
            _ = self.prepare(HEAD, PASSPHRASE + "\nsecond line", pki)
        self.assertIn("only its first line is used", str(caught.exception))

    def test_wrong_passphrase(self) -> None:
        with self.assertRaises(ActionError) as caught:
            _ = self.prepare(HEAD, "not-the-passphrase", build_bundle(self, "sigul"))
        self.assertIn("Could not decrypt sigul-pki", str(caught.exception))

    @unittest.skipUnless(gpg_version() >= (2, 2, 8), "older gpg accepts the bundle")
    def test_bundle_without_integrity_protection_is_explained(self) -> None:
        # The passphrase is right, and gpg still refuses: the caller is
        # told to re-encrypt rather than to check the passphrase.
        base = scratch(self)
        creds, gnupg = base / "creds", base / "gnupg"
        try:
            with self.assertRaises(UnprotectedBundleError) as caught:
                _ = prepare(
                    creds, gnupg, "/sigul-creds", HEAD, PASSPHRASE, NO_MDC_BUNDLE
                )
        finally:
            kill_gpg_agent(gnupg)
        message = str(caught.exception)
        self.assertIn("without integrity protection", message)
        self.assertIn("--cipher-algo AES256", message)
        self.assertNotIn("Could not decrypt", message)
        # Whatever gpg wrote before refusing is gone, with the passphrase
        # and ciphertext; the keyring gpg creates for any home is empty.
        for name in ("passphrase", "pki.gpg", "pki.tar"):
            self.assertFalse((gnupg / name).exists(), name)

    def test_bundle_without_a_database(self) -> None:
        pki = build_bundle(self, "notes", extra={"notes/readme.txt": "x"}, nss=False)
        with self.assertRaises(ActionError) as caught:
            _ = self.prepare(HEAD, PASSPHRASE, pki)
        self.assertIn("No NSS database", str(caught.exception))
        self.assertIn("notes/", str(caught.exception))

    def test_bundle_with_two_databases_is_refused(self) -> None:
        # A backup beside the live database: nss-dir can name one only,
        # and the caller must say which, not the action.
        pki = build_bundle(
            self,
            "sigul",
            extra={"sigul-backup/cert8.db": "", "sigul-backup/key3.db": ""},
        )
        with self.assertRaises(ActionError) as caught:
            _ = self.prepare(HEAD, PASSPHRASE, pki)
        message = str(caught.exception)
        self.assertIn("2 NSS databases", message)
        self.assertIn("sigul/", message)
        self.assertIn("sigul-backup/", message)

    def test_both_formats_in_one_directory_are_one_database(self) -> None:
        # NSS upgrades a database in place, leaving cert8.db beside
        # cert9.db; nss-dir names the directory and the client's NSS
        # chooses the format, as it did for the legacy action. Accepted,
        # and said, since it can explain an unexpected certificate.
        pki = build_bundle(
            self, "sigul", extra={"sigul/cert8.db": "", "sigul/key3.db": ""}
        )
        output = io.StringIO()
        with redirect_stdout(output):
            _, nss_dir = self.prepare(HEAD + ONAP_NSS, PASSPHRASE, pki)
        self.assertEqual(nss_dir, "/sigul-creds/pki/sigul")
        self.assertIn("holds both formats", output.getvalue())

    def test_empty_inputs_and_placeholders(self) -> None:
        pki = build_bundle(self, "sigul")
        for config, password, bundle in (
            ("", PASSPHRASE, pki),
            (HEAD, "", pki),
            (HEAD, PASSPHRASE, " "),
            (HEAD, "\nsecond", pki),
        ):
            with self.assertRaises(ActionError):
                _ = self.prepare(config, password, bundle)
        with self.assertRaises(ActionError):
            _ = self.prepare(HEAD + "user-name: $SIGUL_CONFIG_USR\n", PASSPHRASE, pki)

    def test_top_level_client_conf_cannot_replace_the_callers(self) -> None:
        pki = build_bundle(
            self, "sigul", extra={"client.conf": "[client]\nbridge-port: 9999\n"}
        )
        creds, _ = self.prepare(HEAD + ONAP_NSS, PASSPHRASE, pki)
        config = (creds / "client.conf").read_text()
        self.assertIn("44334", config)
        self.assertNotIn("9999", config)

    def test_bundle_user_configuration_is_layered(self) -> None:
        # sigul_setup_client keeps nss-password in ~/.sigul/client.conf;
        # with HOME at the bundle root, sigul reads it over sigul-conf.
        user = "[nss]\nnss-dir: /home/someone/.sigul\nnss-password: p\n"
        pki = build_bundle(self, ".sigul", extra={".sigul/client.conf": user})
        creds, nss_dir = self.prepare(HEAD, PASSPHRASE, pki)
        layered = (creds / "pki" / ".sigul" / "client.conf").read_text()
        self.assertEqual(self.nss_dirs(layered), [nss_dir])
        self.assertIn("nss-password: p", layered)

    def test_symlinked_user_configuration_is_refused(self) -> None:
        # A link that stays inside the bundle passes extraction, and
        # sigul would follow it to a configuration whose nss-dir was
        # never rewritten, overriding the one that was. The target sits
        # beside the link: Python 3.10.12's filter resolves a relative
        # target against the destination root rather than the link's
        # directory, and would refuse '../real.conf' itself.
        user = "[nss]\nnss-dir: /home/someone/.sigul\nnss-password: p\n"
        pki = build_bundle(
            self,
            ".sigul",
            extra={".sigul/real.conf": user},
            links={".sigul/client.conf": "real.conf"},
        )
        with self.assertRaises(ActionError) as caught:
            _ = self.prepare(HEAD, PASSPHRASE, pki)
        self.assertIn("symlink", str(caught.exception))

    def test_a_bundle_carrying_git_configuration_is_refused(self) -> None:
        # HOME in the container is the bundle, and the legacy image's
        # git reads $HOME/.gitconfig whatever GIT_CONFIG_GLOBAL says.
        for name in (".gitconfig", ".config/git/config"):
            with self.subTest(name=name):
                pki = build_bundle(
                    self, "sigul", extra={name: "[core]\n\tfsmonitor = /bin/true\n"}
                )
                with self.assertRaises(ActionError) as caught:
                    _ = self.prepare(HEAD + ONAP_NSS, PASSPHRASE, pki)
                self.assertIn(name, str(caught.exception))
                self.assertIn("remove it from the bundle", str(caught.exception))

    def test_a_hung_gpgconf_does_not_hold_up_cleanup(self) -> None:
        home = scratch(self)
        never_returns = mock.Mock(side_effect=subprocess.TimeoutExpired("gpgconf", 2))
        output = io.StringIO()
        with (
            mock.patch("gpg_bundle.system_tool", return_value="/usr/bin/gpgconf"),
            mock.patch("gpg_bundle.subprocess.run", never_returns),
            redirect_stdout(output),
        ):
            kill_gpg_agent(home)
        self.assertEqual(never_returns.call_count, 1)
        self.assertIn("::warning::gpgconf did not stop gpg-agent", output.getvalue())

    def test_gpg_leaves_the_users_keyring_alone(self) -> None:
        home = scratch(self)
        # patch.dict restores the environment exactly as it was, an
        # originally unset HOME included.
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            _ = self.prepare(HEAD, PASSPHRASE, build_bundle(self, "sigul"))
        self.assertFalse((home / ".gnupg").exists())


if __name__ == "__main__":
    _ = unittest.main()
