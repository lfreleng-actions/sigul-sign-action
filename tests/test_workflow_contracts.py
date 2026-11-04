# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run workflow assertion steps in isolation, never the credentialed action."""

from __future__ import annotations

import base64
import json
import re
import socket
import subprocess
import textwrap
import unittest
from functools import cached_property
from pathlib import Path
from typing import cast

from tests.helpers import REPOSITORY, scratch


def workflow_steps(filename: str, job: str | None = None) -> list[str]:
    """Read the workflows' six-space-indented steps without a YAML dependency.

    Given a job, read only that job's steps, so jobs may share step names.
    """
    source = (REPOSITORY / ".github" / "workflows" / filename).read_text()
    if job is not None:
        found = re.search(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  \S|\Z)", source)
        if found is None:
            raise ValueError(f"Expected a job named {job!r} in {filename}")
        source = found[1]
    return re.split(r"(?m)^      - ", source)[1:]


def named_step(steps: list[str], name: str) -> str:
    """Require a unique named step, so a renamed/missing assertion fails loudly."""
    matches = [
        step
        for step in steps
        if step.splitlines()[0].removeprefix("name: ").strip("\"'") == name
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected one workflow step named {name!r}")
    return matches[0]


def shell_body(step: str) -> str:
    """Extract only a literal run block, leaving GitHub expressions unevaluated."""
    found = re.search(r"(?m)^        run: \|\n((?:          .*\n|\n)+)", step)
    if found is None or "${{" in found[1]:
        raise ValueError("Expected a literal shell step with inputs passed via env")
    return textwrap.dedent(found[1])


def step_condition(step: str) -> str:
    """A step's if: expression, folded onto one line as YAML reads it."""
    found = re.search(r"(?m)^        if: (>-\n(?:          .*\n)+|.*\n)", step)
    if found is None:
        return ""
    return " ".join(found[1].removeprefix(">-").split())


# Extract at collection time so a broken harness cannot become an expected failure.
LIVE_STEPS = workflow_steps("live-signing.yaml", "live")
VERIFY_STEP = named_step(LIVE_STEPS, "Verify the signature")
VERIFY_SCRIPT = shell_body(VERIFY_STEP)
VALIDATION_STEP = named_step(
    workflow_steps("testing.yaml"), "Assert it failed during validation"
)
VALIDATION_SCRIPT = shell_body(VALIDATION_STEP)

# The readiness guard every live step after the readiness check carries.
READY = "steps.ready.outputs.ready == 'true'"

# Functions intercept every external-service/credential command in these steps.
# No real Docker, Git or GPG is invoked, and mktemp stays inside the test fixture.
STUBS = r"""
docker() {
    [ "$*" = 'image ls -q --no-trunc' ] || return 99
    printf '%s\n' 'sha256:cached-image'
}
gpg() {
    printf 'gpg %s\n' "$*" >> "$COMMAND_LOG"
    case " $* " in
        *' --import '*) cat >/dev/null; return "$IMPORT_STATUS" ;;
        *' --verify '*) return "$VERIFY_STATUS" ;;
        *' --list-keys '*) printf '%s' "$KEY_LISTING" ;;
        *) return 99 ;;
    esac
}
git() {
    printf 'git %s\n' "$*" >> "$COMMAND_LOG"
    case "$1" in
        cat-file) printf '%s\n' '-----BEGIN PGP SIGNATURE-----' ;;
        verify-tag) return "$VERIFY_STATUS" ;;
        *) return 99 ;;
    esac
}
mktemp() { printf '%s\n' "$HOME/gnupg"; }
"""


class WorkflowShellTests(unittest.TestCase):
    @cached_property
    def root(self) -> Path:
        root = scratch(self)
        (root / "gnupg").mkdir()
        return root

    def shell(self, script: str, **env: str) -> subprocess.CompletedProcess[str]:
        """Use a clean environment; never inherit credentials or BASH_ENV."""
        done = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-c", STUBS + script],
            cwd=self.root,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(self.root),
                "RUNNER_TEMP": str(self.root),
                "GITHUB_STEP_SUMMARY": str(self.root / "summary"),
                "COMMAND_LOG": str(self.root / "commands"),
                "IMPORT_STATUS": "0",
                "VERIFY_STATUS": "0",
                "KEY_LISTING": "",
                **env,
            },
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        # Cleanup failures are outside expectedFailure: a broken stub or missing
        # command must not masquerade as a reproduced workflow bug.
        self.addCleanup(
            self.assertNotIn, done.returncode, (99, 126, 127), done.stdout + done.stderr
        )
        return done


class LiveVerificationTests(WorkflowShellTests):
    def verify(
        self,
        operation: str,
        signature: str = "not a PGP signature\n",
        **env: str,
    ) -> subprocess.CompletedProcess[str]:
        _ = (self.root / "payload.txt").write_text("synthetic payload\n")
        _ = (self.root / "payload.txt.asc").write_text(signature)
        return self.shell(
            VERIFY_SCRIPT,
            OPERATION=operation,
            OBJECT="payload.txt",
            **{"PUBLIC_KEY": "synthetic expected public key", **env},
        )

    def test_data_verification_requires_an_expected_key(self) -> None:
        done = self.verify("sign-data", PUBLIC_KEY="")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)

    def test_tag_verification_requires_an_expected_key(self) -> None:
        done = self.verify("sign-git-tag", PUBLIC_KEY="")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)

    def test_expected_key_is_required_before_credentials_are_used(self) -> None:
        unpack = LIVE_STEPS.index(named_step(LIVE_STEPS, "Unpack Sigul credentials"))
        gates = [
            step
            for step in LIVE_STEPS[:unpack]
            if re.search(r"(?m)^          PUBLIC_KEY:.*vars\.SIGUL_PUBLIC_KEY", step)
        ]
        self.assertTrue(gates, "No expected-public-key gate precedes the credentials")
        for step in gates:
            self.assertEqual(
                step_condition(step), f"${{{{ {READY} && env.MODE != 'dry-run' }}}}"
            )
            self.assertNotIn("secrets.", step)
            for mode in ("connection-test", "signing"):
                with self.subTest(mode=mode):
                    done = self.shell(shell_body(step), PUBLIC_KEY="", MODE=mode)
                    self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                    done = self.shell(
                        shell_body(step),
                        PUBLIC_KEY="synthetic expected public key",
                        MODE=mode,
                    )
                    self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_dry_runs_do_not_require_verification(self) -> None:
        self.assertEqual(
            step_condition(VERIFY_STEP), f"${{{{ {READY} && env.MODE == 'signing' }}}}"
        )

    def test_expected_key_is_imported_and_both_operations_are_verified(self) -> None:
        for operation, command in (
            ("sign-data", "gpg --batch --verify payload.txt.asc payload.txt"),
            ("sign-git-tag", "git verify-tag payload.txt"),
        ):
            with self.subTest(operation=operation):
                _ = (self.root / "commands").write_text("")
                done = self.verify(operation)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                calls = (self.root / "commands").read_text()
                self.assertIn("gpg --batch --quiet --import\n", calls)
                self.assertIn(command + "\n", calls)

    def test_signature_verification_failure_fails_the_step(self) -> None:
        for operation in ("sign-data", "sign-git-tag"):
            with self.subTest(operation=operation):
                done = self.verify(operation, VERIFY_STATUS="7")
                self.assertEqual(done.returncode, 7, done.stdout + done.stderr)
                self.assertNotIn("Signature verified", done.stdout)

    def test_public_key_import_failure_fails_the_step(self) -> None:
        for operation in ("sign-data", "sign-git-tag"):
            with self.subTest(operation=operation):
                done = self.verify(operation, IMPORT_STATUS="8")
                self.assertEqual(done.returncode, 8, done.stdout + done.stderr)
                self.assertNotIn("Signature verified", done.stdout)

    def test_unverified_signature_never_reaches_the_summary(self) -> None:
        done = self.verify("sign-data", VERIFY_STATUS="7")
        self.assertEqual(done.returncode, 7, done.stdout + done.stderr)
        summary = self.root / "summary"
        text = summary.read_text() if summary.exists() else ""
        self.assertNotIn("not a PGP signature", text)

    def test_signature_cannot_escape_its_summary_block(self) -> None:
        # Armour headers are not covered by the signature, so even a
        # verified file can carry text that closes a fixed fence.
        hostile = (
            "-----BEGIN PGP SIGNATURE-----\n"
            "Comment: ```\n"
            "Comment: x\r# Injected after a bare carriage return\n"
            "```\n"
            "# Injected heading\n"
            '<img src="https://example.invalid/x">\n'
            "-----END PGP SIGNATURE-----\n"
        )
        done = self.verify("sign-data", signature=hostile)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        summary = (self.root / "summary").read_text()
        self.assertIn("# Injected heading", summary)
        for line in summary.splitlines():
            if any(mark in line for mark in ("Injected", "<img", "```", "PGP")):
                with self.subTest(line=line):
                    self.assertTrue(line.startswith("    "), line)


class ExpectedBridgeContractTests(unittest.TestCase):
    def test_expected_bridge_is_optional_and_defaults_to_empty(self) -> None:
        source = (REPOSITORY / "action.yaml").read_text()
        field = re.search(r"(?m)^  expected-bridge:\n(?:    .*\n|\n)+", source)
        self.assertIsNotNone(field, "The optional expected-bridge input is missing")
        if field is not None:
            self.assertRegex(field[0], r"(?m)^    required: false$")
            self.assertRegex(field[0], r"(?m)^    default: (\"\"|'')$")

    def test_both_action_steps_receive_the_expected_bridge_input(self) -> None:
        source = (REPOSITORY / "action.yaml").read_text()
        steps = re.split(r"(?m)^    - ", source)[1:]
        for name in ("Validate inputs", "Sign with Sigul"):
            with self.subTest(step=name):
                step = named_step(steps, name)
                self.assertIn("EXPECTED_BRIDGE: ${{ inputs.expected-bridge }}", step)

    def test_live_signing_passes_the_approved_host_and_port_as_an_expectation(
        self,
    ) -> None:
        step = named_step(LIVE_STEPS, "Sign with Sigul")
        self.assertIn(
            "expected-bridge: ${{ format('{0}:44334', env.BRIDGE_HOST) }}", step
        )


def harden_runner_allowlist() -> str:
    """The live workflow's allowed-endpoints value, as written in YAML."""
    step = named_step(LIVE_STEPS, "Harden runner (block)")
    found = re.search(
        r"(?m)^          allowed-endpoints: >-\n((?:            .*\n)+)", step
    )
    if found is None:
        raise ValueError("Expected a folded allowed-endpoints block")
    return found[1]


class LiveAllowlistTests(unittest.TestCase):
    def test_allowlist_is_one_expression(self) -> None:
        # harden-runner's agent splits allowed-endpoints on spaces only. A
        # folded block keeps the line breaks around its indented
        # continuation lines, so separate lines reach the agent joined by
        # newlines and fuse into one entry: the bridge was blocked and
        # resolved to a sinkhole address. A single expression yields one
        # line, whatever its source layout.
        block = harden_runner_allowlist().strip()
        self.assertTrue(
            block.startswith("${{")
            and block.endswith("}}")
            and block.count("${{") == 1,
            block,
        )

    def test_allowlist_names_every_endpoint(self) -> None:
        block = harden_runner_allowlist()
        for endpoint in (
            "github.com:443",
            "ghcr.io:443",
            "pkg-containers.githubusercontent.com:443",
            "auth.docker.io:443",
            "registry-1.docker.io:443",
            "production.cloudflare.docker.com:443",
            "production.cloudfront.docker.com:443",
            "sigul-bridge-yul.linuxfoundation.org",
            "sigul-bridge-us-west-2.linuxfoundation.org",
            "sigul-bridge.opensearch.org:44334",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertIn(endpoint, block)


class LiveBridgeSelectionTests(WorkflowShellTests):
    def test_existing_allowlist_accepts_only_the_selected_infrastructure(self) -> None:
        script = shell_body(named_step(LIVE_STEPS, "Check the selected bridge"))
        for container, host, status in (
            ("legacy", "sigul-bridge-yul.linuxfoundation.org", 0),
            ("legacy", "sigul-bridge-us-west-2.linuxfoundation.org", 0),
            ("modern", "sigul-bridge.opensearch.org", 0),
            ("modern", "sigul-bridge-yul.linuxfoundation.org", 1),
            ("legacy", "sigul-bridge.opensearch.org", 1),
            ("modern", "unapproved-bridge.invalid", 1),
            ("modern", "", 1),
        ):
            with self.subTest(container=container, host=host):
                done = self.shell(script, CONTAINER=container, BRIDGE_HOST=host)
                self.assertEqual(done.returncode, status, done.stdout + done.stderr)


def live_script(name: str) -> str:
    """Look a new step up per test, so its absence is the expected failure."""
    return shell_body(named_step(LIVE_STEPS, name))


def credentials(**fields: object) -> str:
    """Encode a SIGUL_CREDENTIALS document the way maintainers store it."""
    document = {"version": 1, **fields}
    return base64.b64encode(json.dumps(document).encode()).decode()


# Synthetic values, each distinctive enough to spot if an error leaks it.
CONFIG = base64.b64encode(b"[client]\nbridge-hostname: bridge.invalid\n").decode()
PHRASE = "synthetic phrase"
PKI = base64.b64encode(b"-----BEGIN PGP MESSAGE-----\nsynthetic\n").decode()
VALID = {"config": CONFIG, "password": PHRASE, "pki": PKI}


class LiveCredentialTests(WorkflowShellTests):
    def unpack(self, value: str) -> subprocess.CompletedProcess[str]:
        done = self.shell(
            live_script("Unpack Sigul credentials"),
            SIGUL_CREDENTIALS=value,
            GITHUB_OUTPUT=str(self.root / "output"),
        )
        self.addCleanup(self.assertNotIn, "Traceback", done.stdout + done.stderr)
        return done

    def assert_refused(self, value: str, *secrets: str) -> None:
        done = self.unpack(value)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("::error::", done.stdout + done.stderr)
        self.assertFalse((self.root / "output").exists())
        for secret in (PHRASE, CONFIG, PKI, *secrets):
            self.assertNotIn(secret, done.stdout + done.stderr)

    def test_valid_document_writes_every_field(self) -> None:
        done = self.unpack(credentials(**VALID))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(
            (self.root / "output").read_text(),
            f"config={CONFIG}\npassword={PHRASE}\npki={PKI}\n",
        )
        for value in VALID.values():
            self.assertIn(f"::add-mask::{value}\n", done.stdout)

    def test_line_wrapped_base64_is_accepted(self) -> None:
        wrapped = "\n".join(textwrap.wrap(credentials(**VALID), 76))
        done = self.unpack(wrapped)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_every_field_is_masked_before_any_output_is_written(self) -> None:
        # An unwritable output file fails at the write; the masks must be out.
        done = self.shell(
            live_script("Unpack Sigul credentials"),
            SIGUL_CREDENTIALS=credentials(**VALID),
            GITHUB_OUTPUT=str(self.root / "missing" / "output"),
        )
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)
        for value in VALID.values():
            self.assertIn(f"::add-mask::{value}\n", done.stdout)

    def test_non_base64_is_refused(self) -> None:
        self.assert_refused(f"!{PHRASE}!")

    def test_non_json_is_refused(self) -> None:
        text = base64.b64encode(f"not json {PHRASE}".encode()).decode()
        self.assert_refused(text)

    def test_unsupported_versions_are_refused(self) -> None:
        for version in (None, 0, 2, "1"):
            with self.subTest(version=version):
                self.assert_refused(credentials(**{**VALID, "version": version}))

    def test_missing_empty_or_multi_line_fields_are_refused(self) -> None:
        for key in VALID:
            for value in (None, "", 7, f"{PHRASE}\nsecond", f"{PHRASE}\rsecond"):
                with self.subTest(key=key, value=value):
                    fields: dict[str, object] = {**VALID, key: value}
                    if value is None:
                        del fields[key]
                    done = self.unpack(credentials(**fields))
                    self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                    self.assertIn(f"SIGUL_CREDENTIALS.{key}", done.stderr)
                    self.assertFalse((self.root / "output").exists())
                    for secret in VALID.values():
                        self.assertNotIn(secret, done.stderr)

    def test_percent_escapes_are_masked_literally(self) -> None:
        # The runner percent-decodes command data, so "%25" in the mask
        # must arrive as "%2525" to register the value itself.
        phrase = "prefix:%25suffix"
        done = self.unpack(credentials(**{**VALID, "password": phrase}))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("::add-mask::prefix:%2525suffix\n", done.stdout)
        self.assertNotIn(f"::add-mask::{phrase}\n", done.stdout)
        self.assertEqual(
            (self.root / "output").read_text(),
            f"config={CONFIG}\npassword={phrase}\npki={PKI}\n",
        )


def bound_port(sock: socket.socket) -> int:
    """Return the port an IPv4 socket is bound to."""
    _, port = cast(tuple[str, int], sock.getsockname())
    return port


class LiveBridgePinTests(WorkflowShellTests):
    def pin(self, host: str, port: int) -> subprocess.CompletedProcess[str]:
        done = self.shell(
            live_script("Pin the bridge address"),
            BRIDGE_HOST=host,
            BRIDGE_PORT=str(port),
            GITHUB_OUTPUT=str(self.root / "output"),
        )
        self.addCleanup(self.assertNotIn, "Traceback", done.stdout + done.stderr)
        return done

    def closed_port(self) -> int:
        """Return a loopback port nothing listens on."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return bound_port(probe)

    def test_first_accepting_address_is_pinned(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            done = self.pin("localhost", bound_port(listener))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual((self.root / "output").read_text(), "address=127.0.0.1\n")
        self.assertIn("::notice::Pinned localhost to 127.0.0.1", done.stdout)

    def test_no_accepting_address_fails(self) -> None:
        done = self.pin("localhost", self.closed_port())
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("::error::", done.stdout + done.stderr)
        self.assertIn("127.0.0.1", done.stdout + done.stderr)
        self.assertFalse((self.root / "output").exists())

    def test_a_name_the_resolver_rejects_fails(self) -> None:
        # glibc refuses a name with a space before any lookup, so this
        # stays off the network on every runner.
        done = self.pin("bad name.invalid", self.closed_port())
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("::error::", done.stdout + done.stderr)
        self.assertIn("bad name.invalid", done.stdout + done.stderr)
        self.assertFalse((self.root / "output").exists())


# The readiness check's environment when the project is fully set up.
COMPLETE_PROJECT = {
    "PROJECT": "synthetic-project",
    "HAVE_CREDENTIALS": "true",
    "SIGUL_KEY": "synthetic-key",
    "SIGUL_URI": "sigul-bridge.opensearch.org",
    "SIGUL_PUBLIC_KEY": "synthetic expected public key",
}


class LiveReadinessTests(WorkflowShellTests):
    def check(self, **env: str) -> tuple[subprocess.CompletedProcess[str], str]:
        output = self.root / "output"
        done = self.shell(
            live_script("Check environment readiness"),
            GITHUB_OUTPUT=str(output),
            **{**COMPLETE_PROJECT, **env},
        )
        return done, output.read_text() if output.exists() else ""

    def test_complete_configuration_is_ready(self) -> None:
        done, output = self.check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(output, "ready=true\n")
        self.assertNotIn("::notice::", done.stdout)

    def test_each_missing_item_skips_cleanly_and_is_named(self) -> None:
        for variable, value, item in (
            ("HAVE_CREDENTIALS", "false", "secret SIGUL_CREDENTIALS"),
            ("SIGUL_KEY", "", "variable SIGUL_KEY"),
            ("SIGUL_KEY", " ", "variable SIGUL_KEY"),
            ("SIGUL_URI", "", "variable SIGUL_URI"),
            ("SIGUL_PUBLIC_KEY", "\n", "variable SIGUL_PUBLIC_KEY"),
        ):
            with self.subTest(variable=variable, value=value):
                (self.root / "output").unlink(missing_ok=True)
                done, output = self.check(**{variable: value})
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(output, "ready=false\n")
                self.assertIn(
                    f"::notice::synthetic-project: not configured, missing {item};"
                    + " skipping\n",
                    done.stdout,
                )

    def test_every_missing_item_is_named_in_one_notice(self) -> None:
        done, output = self.check(
            HAVE_CREDENTIALS="false", SIGUL_KEY="", SIGUL_URI="", SIGUL_PUBLIC_KEY=""
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(output, "ready=false\n")
        notices = [line for line in done.stdout.splitlines() if "::notice::" in line]
        self.assertEqual(len(notices), 1, done.stdout)
        for item in ("SIGUL_CREDENTIALS", "SIGUL_KEY", "SIGUL_URI", "SIGUL_PUBLIC_KEY"):
            self.assertIn(item, notices[0])

    def test_readiness_reads_no_secret_value(self) -> None:
        step = named_step(LIVE_STEPS, "Check environment readiness")
        self.assertRegex(step, r"(?m)^        id: ready$")
        self.assertIn("HAVE_CREDENTIALS: ${{ secrets.SIGUL_CREDENTIALS != '' }}", step)
        self.assertEqual(
            re.findall(r"secrets\.\w+", step), ["secrets.SIGUL_CREDENTIALS"]
        )

    def test_every_later_step_is_guarded_by_readiness(self) -> None:
        ready = LIVE_STEPS.index(named_step(LIVE_STEPS, "Check environment readiness"))
        for step in LIVE_STEPS[ready + 1 :]:
            with self.subTest(step=step.splitlines()[0]):
                condition = step_condition(step)
                self.assertTrue(condition.startswith(f"${{{{ {READY}"), condition)


# gpg --with-colons output for a primary key and one subkey.
PRIMARY = "A" * 40
SUBKEY = "B" * 40
OTHER = "C" * 40


def key_listing(primary: str = PRIMARY, *subkeys: str) -> str:
    """Colon listing as gpg --with-subkey-fingerprint --list-keys prints it."""
    lines = [
        "pub:-:4096:1:0000:0:::-:::scESC::::::23::0:",
        f"fpr:::::::::{primary}:",
    ]
    for subkey in subkeys:
        lines += ["sub:-:4096:1:0001:0:::::e::::::23:", f"fpr:::::::::{subkey}:"]
    lines.append("uid:-::::0::0000::Synthetic <synthetic@example.invalid>::::::::::0:")
    return "\n".join(lines) + "\n"


class LiveKeyComparisonTests(WorkflowShellTests):
    def compare(
        self, fingerprints: str, listing: str
    ) -> subprocess.CompletedProcess[str]:
        _ = (self.root / "commands").write_text("")
        return self.shell(
            live_script("Compare the server's key"),
            FINGERPRINTS=fingerprints,
            PUBLIC_KEY="synthetic expected public key",
            KEY_LISTING=listing,
        )

    def test_matching_keys_pass(self) -> None:
        done = self.compare(f"{PRIMARY} {SUBKEY}", key_listing(PRIMARY, SUBKEY))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertNotIn("::warning::", done.stdout)
        self.assertIn(PRIMARY, (self.root / "summary").read_text())
        calls = (self.root / "commands").read_text()
        self.assertIn("gpg --batch --quiet --import\n", calls)

    def test_case_differences_are_not_a_mismatch(self) -> None:
        done = self.compare(PRIMARY.lower(), key_listing(PRIMARY))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_different_primary_key_fails(self) -> None:
        done = self.compare(f"{OTHER} {SUBKEY}", key_listing(PRIMARY, SUBKEY))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("::error::", done.stdout)
        self.assertIn(OTHER, done.stdout)

    def test_no_returned_fingerprint_fails(self) -> None:
        done = self.compare("", key_listing(PRIMARY))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("::error::", done.stdout)

    def test_an_expected_key_without_one_primary_fails(self) -> None:
        for listing in ("", key_listing(PRIMARY) + key_listing(OTHER)):
            with self.subTest(listing=listing):
                done = self.compare(PRIMARY, listing)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn("exactly one primary key", done.stdout)

    def test_a_subkey_difference_only_warns(self) -> None:
        for returned, expected in (
            (f"{PRIMARY} {OTHER}", (SUBKEY,)),
            (PRIMARY, (SUBKEY,)),
            (f"{PRIMARY} {SUBKEY} {OTHER}", (SUBKEY,)),
        ):
            with self.subTest(returned=returned):
                done = self.compare(returned, key_listing(PRIMARY, *expected))
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                warnings = [
                    line for line in done.stdout.splitlines() if "::warning::" in line
                ]
                self.assertEqual(len(warnings), 1, done.stdout)
                self.assertTrue(OTHER in warnings[0] or SUBKEY in warnings[0])

    def test_comparison_reads_the_connection_test_output(self) -> None:
        step = named_step(LIVE_STEPS, "Compare the server's key")
        self.assertIn(
            "FINGERPRINTS: ${{ steps.connect.outputs.public_key_fingerprints }}", step
        )
        self.assertEqual(
            step_condition(step),
            f"${{{{ {READY} && env.MODE == 'connection-test' }}}}",
        )


def job_step(job: str, name: str) -> str:
    """Look a step of another live-signing job up per test, like live_script."""
    return named_step(workflow_steps("live-signing.yaml", job), name)


HOME_REPOSITORY = "lfreleng-actions/sigul-sign-action"
PROJECTS = {
    "alpha": {"container": "legacy", "enabled": True},
    "beta": {"container": "modern", "enabled": True},
    "gamma": {"container": "legacy", "enabled": False},
}


class ResolveTests(WorkflowShellTests):
    def resolve(
        self,
        names: list[str] | None = None,
        projects: object = PROJECTS,
        **env: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
        output = self.root / "output"
        output.unlink(missing_ok=True)
        done = self.shell(
            shell_body(job_step("resolve", "Select the projects")),
            **{
                "NAMES": json.dumps(names or []),
                "SIGUL_LIVE_PROJECTS": (
                    projects if isinstance(projects, str) else json.dumps(projects)
                ),
                "EVENT_NAME": "workflow_dispatch",
                "MODE_INPUT": "dry-run",
                "REF": "refs/heads/main",
                "REPOSITORY": HOME_REPOSITORY,
                "GITHUB_OUTPUT": str(output),
                **env,
            },
        )
        self.addCleanup(self.assertNotIn, "Traceback", done.stdout + done.stderr)
        lines = output.read_text().splitlines() if output.exists() else []
        return done, dict(line.split("=", 1) for line in lines)

    def assert_selected(
        self, outputs: dict[str, str], *projects: tuple[str, str]
    ) -> None:
        self.assertEqual(
            json.loads(outputs["matrix"]),
            [{"project": name, "container": kind} for name, kind in projects],
        )
        self.assertEqual(outputs["count"], str(len(projects)))

    def test_blank_input_selects_every_enabled_project(self) -> None:
        cases: tuple[list[str] | None, ...] = (None, [])
        for names in cases:
            with self.subTest(names=names):
                done, outputs = self.resolve(names)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assert_selected(outputs, ("alpha", "legacy"), ("beta", "modern"))
                self.assertEqual(outputs["mode"], "dry-run")
                self.assertNotIn("::warning::", done.stdout)

    def test_named_projects_are_selected_in_order(self) -> None:
        done, outputs = self.resolve(["beta", "alpha"], MODE_INPUT="signing")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assert_selected(outputs, ("beta", "modern"), ("alpha", "legacy"))
        self.assertEqual(outputs["mode"], "signing")
        summary = (self.root / "summary").read_text()
        self.assertIn("`beta` (modern)", summary)

    def test_every_unknown_name_is_reported(self) -> None:
        done, outputs = self.resolve(["delta", "beta", "zeta"])
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        errors = [line for line in done.stdout.splitlines() if "::error::" in line]
        self.assertEqual(len(errors), 2, done.stdout)
        self.assertIn("delta", errors[0])
        self.assertIn("zeta", errors[1])
        self.assertEqual(outputs, {})

    def test_a_disabled_name_is_skipped_with_a_warning(self) -> None:
        done, outputs = self.resolve(["gamma", "beta"])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assert_selected(outputs, ("beta", "modern"))
        self.assertIn(
            "::warning::Skipping gamma: disabled in SIGUL_LIVE_PROJECTS\n", done.stdout
        )
        self.assertIn("`gamma`", (self.root / "summary").read_text())

    def test_only_disabled_names_select_nothing(self) -> None:
        done, outputs = self.resolve(["gamma"])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assert_selected(outputs)

    def test_names_ignore_case_and_duplicates(self) -> None:
        done, outputs = self.resolve(["BETA", "alpha", "beta", "Alpha"])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assert_selected(outputs, ("beta", "modern"), ("alpha", "legacy"))

    def test_a_schedule_tests_the_connection_of_every_enabled_project(self) -> None:
        done, outputs = self.resolve(EVENT_NAME="schedule", MODE_INPUT="")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(outputs["mode"], "connection-test")
        self.assert_selected(outputs, ("alpha", "legacy"), ("beta", "modern"))

    def test_bad_configuration_fails(self) -> None:
        for projects in (
            "",
            "{not json",
            "[]",
            "{}",
            {"alpha": "legacy"},
            {"alpha": {"container": "bespoke", "enabled": True}},
            {"alpha": {"enabled": True}},
            {"alpha": {"container": "legacy", "enabled": "true"}},
            {"alpha": {"container": "legacy"}},
            {
                "alpha": {"container": "legacy", "enabled": True},
                "ALPHA": {"container": "legacy", "enabled": True},
            },
        ):
            with self.subTest(projects=projects):
                done, outputs = self.resolve(projects=projects)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn("::error::", done.stdout)
                self.assertIn("SIGUL_LIVE_PROJECTS", done.stdout)
                self.assertEqual(outputs, {})

    def test_every_configuration_error_is_reported(self) -> None:
        done, _ = self.resolve(
            projects={
                "alpha": {"container": "bespoke", "enabled": True},
                "beta": {"container": "modern", "enabled": 1},
            }
        )
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("alpha.container", done.stdout)
        self.assertIn("beta.enabled", done.stdout)

    def test_off_main_selects_nothing_with_a_notice(self) -> None:
        for env in (
            {"REF": "refs/heads/feature"},
            {"REF": "refs/pull/7/merge"},
            {"REPOSITORY": "someone/sigul-sign-action"},
        ):
            with self.subTest(env=env):
                # Even a missing configuration ends cleanly off main.
                done, outputs = self.resolve(["zeta"], projects="", **env)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertIn("::notice::", done.stdout)
                self.assertIn("only the main branch", done.stdout)
                self.assert_selected(outputs)

    def test_configuration_reaches_the_script_through_env(self) -> None:
        step = job_step("resolve", "Select the projects")
        self.assertIn("SIGUL_LIVE_PROJECTS: ${{ vars.SIGUL_LIVE_PROJECTS }}", step)
        self.assertNotIn("secrets.", LIVE_SOURCE.split("\n  live:\n")[0])

    def test_the_input_is_split_by_the_pinned_list_splitter(self) -> None:
        step = job_step("resolve", "Split the projects input")
        self.assertIn(
            "uses: lfreleng-actions/list-splitter-action@"
            + "b56a625474875d05ca8d1c1eb3314c29c526c9a6  # v0.1.0",
            step,
        )
        self.assertIn("validate: 'none'", step)
        self.assertIn(
            "NAMES: ${{ steps.split.outputs.json }}",
            job_step("resolve", "Select the projects"),
        )


LIVE_SOURCE = (REPOSITORY / ".github" / "workflows" / "live-signing.yaml").read_text()

# Each mode's action call, and the inputs only it passes.
ACTION_CALLS = {
    "Dry run with Sigul": (
        "dry-run",
        ("sign-type: sign-data", 'dry-run: "true"'),
    ),
    "Check the connection with Sigul": (
        "connection-test",
        ("sign-type: check-connection",),
    ),
    "Sign with Sigul": (
        "signing",
        ("sign-type: ${{ inputs.operation }}", 'push-tag: "false"'),
    ),
}


class LiveSigningWiringTests(unittest.TestCase):
    def test_each_mode_uses_the_unpacked_credentials_and_the_pin(self) -> None:
        for name, (mode, extra) in ACTION_CALLS.items():
            step = named_step(LIVE_STEPS, name)
            self.assertEqual(
                step_condition(step), f"${{{{ {READY} && env.MODE == '{mode}' }}}}"
            )
            for line in (
                "uses: $/",
                "container: ${{ matrix.container }}",
                "allow-legacy: ${{ matrix.container == 'legacy' }}",
                "sigul-key-name: ${{ vars.SIGUL_KEY }}",
                "sigul-conf: ${{ steps.creds.outputs.config }}",
                "sigul-pass: ${{ steps.creds.outputs.password }}",
                "sigul-pki: ${{ steps.creds.outputs.pki }}",
                "sigul-ip: ${{ steps.pin.outputs.address }}",
                "sigul-uri: ${{ env.BRIDGE_HOST }}",
                'sigul-hosts-entry: "true"',
                "expected-bridge: ${{ format('{0}:44334', env.BRIDGE_HOST) }}",
                *extra,
            ):
                with self.subTest(step=name, line=line):
                    self.assertIn(" " + line + "\n", " " + step.strip() + "\n")
        connect = named_step(LIVE_STEPS, "Check the connection with Sigul")
        self.assertNotIn("sign-object:", connect)
        self.assertRegex(connect, r"(?m)^        id: connect$")

    def test_retired_secrets_and_inputs_are_gone(self) -> None:
        for retired in (
            "secrets.SIGUL_CONF",
            "secrets.SIGUL_PASS",
            "secrets.SIGUL_PKI",
            "secrets.SIGUL_IP",
            "secrets.SIGUL_URI",
            "secrets.SIGUL_KEY",
            "inputs.container",
            "inputs.allow-legacy",
            "inputs.dry-run",
            "inputs.project ",
            "inputs.project }",
            "env.CONTAINER",
            "sigul-${{",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, LIVE_SOURCE)

    def test_no_project_is_named_in_the_workflow(self) -> None:
        for project in ("onap", "opendaylight", "o-ran-sc", 'opensearch"'):
            with self.subTest(project=project):
                self.assertNotIn(project, LIVE_SOURCE.lower())

    def test_job_runs_in_each_selected_project_environment(self) -> None:
        live = LIVE_SOURCE.split("\n  live:\n", 1)[1].split("\n  notify-slack:\n")[0]
        for line in (
            "    environment: ${{ matrix.project }}",
            "    needs: resolve",
            "    if: ${{ needs.resolve.outputs.count != '0' }}",
            "      fail-fast: false",
            "        include: ${{ fromJSON(needs.resolve.outputs.matrix) }}",
            "      BRIDGE_HOST: ${{ vars.SIGUL_URI }}",
        ):
            with self.subTest(line=line):
                self.assertIn(line + "\n", live)

    def test_triggers_and_inputs(self) -> None:
        self.assertIn("    - cron: '17 */6 * * *'\n", LIVE_SOURCE)
        self.assertRegex(
            LIVE_SOURCE,
            r"(?m)^      mode:\n(?:        .*\n)*?"
            + r'        options: \["dry-run", "connection-test", "signing"\]\n'
            + r'        default: "dry-run"$',
        )
        self.assertRegex(
            LIVE_SOURCE,
            r"(?m)^      projects:\n(?:        .*\n)*?        type: string$",
        )
        self.assertRegex(
            LIVE_SOURCE,
            r"(?m)^      operation:\n(?:        .*\n)*?"
            + r'        options: \["sign-data", "sign-git-tag"\]$',
        )
        self.assertIn("  GH_TELEMETRY: 'false'\n", LIVE_SOURCE)


GH_STUB = r"""
gh() {
    printf 'gh %s\n' "$*" >> "$COMMAND_LOG"
    [ "$1" = api ] || return 99
    [ -e "$HOME/api-fails" ] && { echo partial; return 1; }
    cat "$HOME/api-response"
}
"""


class NotifySlackTests(WorkflowShellTests):
    def summarise(self, *jobs: object) -> tuple[subprocess.CompletedProcess[str], str]:
        _ = (self.root / "api-response").write_text(
            "".join(json.dumps(job) + "\n" for job in jobs)
        )
        output = self.root / "output"
        done = self.shell(
            GH_STUB + shell_body(job_step("notify-slack", "List the failed jobs")),
            REPOSITORY=HOME_REPOSITORY,
            RUN_ID="42",
            RUN_ATTEMPT="1",
            GITHUB_OUTPUT=str(output),
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        name, value = output.read_text().strip().split("=", 1)
        self.assertEqual(name, "summary")
        return done, cast(str, json.loads(value))

    def test_failed_and_cancelled_jobs_name_their_first_failed_step(self) -> None:
        def step(name: str, conclusion: str) -> dict[str, str]:
            return {"name": name, "conclusion": conclusion}

        _, summary = self.summarise(
            {"name": "Select projects", "conclusion": "success", "steps": []},
            {
                "name": "connection-test: alpha",
                "conclusion": "failure",
                "steps": [
                    step("Check environment readiness", "success"),
                    step("Check the selected bridge", "failure"),
                    step("Compare the server's key", "skipped"),
                ],
            },
            {
                "name": "connection-test: beta",
                "conclusion": "cancelled",
                "steps": [step("Check the connection with Sigul", "cancelled")],
            },
            {"name": "connection-test: <b>", "conclusion": "success", "steps": []},
            {"name": "Notify Slack on failure", "conclusion": None, "steps": []},
        )
        self.assertEqual(
            summary.splitlines(),
            [
                "• *connection-test: alpha* (failure): Check the selected bridge",
                "• *connection-test: beta* (cancelled): "
                + "Check the connection with Sigul",
            ],
        )
        calls = (self.root / "commands").read_text()
        self.assertIn(
            "repos/lfreleng-actions/sigul-sign-action/actions/runs/42/attempts/1/jobs",
            calls,
        )

    def test_timed_out_job_is_named(self) -> None:
        _, summary = self.summarise(
            {
                "name": "connection-test: gamma",
                "conclusion": "timed_out",
                "steps": [
                    {"name": "Check environment readiness", "conclusion": "success"},
                    {"name": "Sign with Sigul", "conclusion": "cancelled"},
                ],
            }
        )
        self.assertEqual(
            summary, "• *connection-test: gamma* (timed_out): Sign with Sigul"
        )

    def test_slack_markup_in_names_is_escaped(self) -> None:
        _, summary = self.summarise(
            {"name": "x <!channel> & y", "conclusion": "failure", "steps": []}
        )
        self.assertIn("x &lt;!channel&gt; &amp; y", summary)
        self.assertIn("no failed step recorded", summary)

    def test_failed_job_lookup_still_produces_the_generic_alert(self) -> None:
        _ = (self.root / "api-fails").write_text("")
        done, summary = self.summarise()
        self.assertIn("::warning::Could not list this run's jobs", done.stdout)
        self.assertEqual(summary, "No failed job was found; see the run.")

    def test_notification_is_scheduled_failures_only(self) -> None:
        notify = LIVE_SOURCE.split("\n  notify-slack:\n", 1)[1]
        condition = " ".join(
            notify.split("    if: >-\n", 1)[1].split("\n    runs-on")[0].split()
        )
        self.assertEqual(
            condition,
            "${{ always() && github.event_name == 'schedule' && "
            + "(contains(needs.*.result, 'failure') || "
            + "contains(needs.*.result, 'cancelled')) }}",
        )
        for line in (
            "    needs: [resolve, live]",
            "    environment: notifications",
            "      actions: read  #",
            "            api.github.com:443 slack.com:443",
            '          token: "${{ secrets.SLACK_BOT_TOKEN }}"',
            "          method: 'chat.postMessage'",
            "          errors: 'true'",
        ):
            with self.subTest(line=line):
                self.assertIn(line, notify)


class ValidationAssertionTests(WorkflowShellTests):
    def assertion(
        self, outcome: str = "failure", status: str = "rejected"
    ) -> subprocess.CompletedProcess[str]:
        # Both cached-image and failed-pull paths can leave this list unchanged.
        _ = (self.root / "images-before").write_text("sha256:cached-image\n")
        return self.shell(
            VALIDATION_SCRIPT,
            CASE="invalid input",
            OUTCOME=outcome,
            VALIDATION_STATUS=status,
        )

    def assert_not_rejected(
        self, outcome: str = "failure", status: str = "rejected"
    ) -> None:
        done = self.assertion(outcome, status)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertNotIn("Rejected during validation", done.stdout)

    def test_failure_with_rejected_status_is_accepted(self) -> None:
        done = self.assertion()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("Rejected during validation", done.stdout)

    def test_success_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(outcome="success")

    def test_validation_status_is_wired_to_the_action_output(self) -> None:
        self.assertRegex(
            VALIDATION_STEP,
            r"(?m)^          VALIDATION_STATUS: [\"']?"
            + r"\$\{\{ steps\.invalid\.outputs\.validation_status \}\}[\"']?$",
        )

    def test_empty_outcome_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(outcome="")

    def test_cancelled_outcome_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(outcome="cancelled")

    def test_skipped_outcome_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(outcome="skipped")

    def test_unknown_outcome_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(outcome="unknown")

    def test_failure_without_validation_status_is_not_a_rejection(self) -> None:
        self.assert_not_rejected(status="")

    def test_failure_after_validation_passed_is_not_a_rejection(self) -> None:
        self.assert_not_rejected(status="passed")

    def test_bootstrap_failure_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(status="bootstrap")

    def test_unknown_status_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(status="unknown")

    def test_success_status_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(status="success")

    def test_cancelled_status_is_not_a_validation_rejection(self) -> None:
        self.assert_not_rejected(status="cancelled")


TESTING_STEPS = workflow_steps("testing.yaml")


def step_inputs(name: str) -> dict[str, str]:
    """The with: block of a named step, as written, unevaluated."""
    step = named_step(TESTING_STEPS, name)
    found = re.search(r"(?m)^        with:\n((?:          .*\n)+)", step)
    if found is None:
        raise ValueError(f"Expected a with: block in {name!r}")
    pairs = (
        line.strip().split(": ", 1)
        for line in found[1].splitlines()
        # Keys only: deeper lines continue a block scalar's value.
        if not line.startswith(" " * 11) and ": " in line
    )
    return {key: value.strip("\"'") for key, value in pairs}


WRONG_CHECK = "Check the connection with a wrong passphrase (should fail)"
ALTERNATE_DRY_RUN = "Dry run with the alternate bundle"


class WrongPassphraseWiringTests(unittest.TestCase):
    """The wrong-passphrase check must fail at the server, not on the runner.

    The action decrypts sigul-pki with sigul-pass before the client
    runs. With the main bundle and any other passphrase, decryption
    fails first, and the check passes without exercising the server's
    passphrase check at all.
    """

    def test_the_bundle_decrypts_with_the_wrong_passphrase(self) -> None:
        inputs = step_inputs(WRONG_CHECK)
        self.assertEqual(
            inputs["sigul-pki"], "${{ steps.setup.outputs.alternate_pki }}"
        )
        self.assertEqual(
            inputs["sigul-pass"], "${{ steps.setup.outputs.alternate_passphrase }}"
        )

    def test_a_dry_run_shows_the_alternate_bundle_decrypts(self) -> None:
        # A dry run decrypts the bundle and opens the NSS database, but
        # never sends the passphrase to the client, so it passes with
        # any passphrase that decrypts the bundle.
        inputs = step_inputs(ALTERNATE_DRY_RUN)
        self.assertEqual(inputs["dry-run"], "true")
        self.assertEqual(
            inputs["sigul-pki"], "${{ steps.setup.outputs.alternate_pki }}"
        )
        self.assertEqual(
            inputs["sigul-pass"], "${{ steps.setup.outputs.alternate_passphrase }}"
        )
        check = named_step(TESTING_STEPS, "Assert the connection checks")
        self.assertIn("steps.alternate_dry_run.outcome", check)

    def test_both_bundles_hold_the_same_archive(self) -> None:
        # So the only difference between the passing check and the
        # failing one is the passphrase the server receives.
        source = (REPOSITORY / "tests" / "make-test-credentials.sh").read_text()
        self.assertIn("alternate-pki.asc", source)
        self.assertIn("cmp ", source)


if __name__ == "__main__":
    _ = unittest.main()
