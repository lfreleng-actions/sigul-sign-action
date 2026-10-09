# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run workflow assertion steps in isolation, never the credentialed action."""

from __future__ import annotations

import re
import subprocess
import textwrap
import unittest
from functools import cached_property
from pathlib import Path

from tests.helpers import REPOSITORY, scratch


def workflow_steps(filename: str) -> list[str]:
    """Read the workflows' six-space-indented steps without a YAML dependency."""
    source = (REPOSITORY / ".github" / "workflows" / filename).read_text()
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


# Extract at collection time so a broken harness cannot become an expected failure.
LIVE_STEPS = workflow_steps("live-signing.yaml")
VERIFY_STEP = named_step(LIVE_STEPS, "Verify the signature")
VERIFY_SCRIPT = shell_body(VERIFY_STEP)
VALIDATION_STEP = named_step(
    workflow_steps("testing.yaml"), "Assert it failed during validation"
)
VALIDATION_SCRIPT = shell_body(VALIDATION_STEP)

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
        signing = LIVE_STEPS.index(named_step(LIVE_STEPS, "Sign with Sigul"))
        gates = [
            step
            for step in LIVE_STEPS[:signing]
            if re.search(r"(?m)^          PUBLIC_KEY:.*vars\.SIGUL_PUBLIC_KEY", step)
        ]
        self.assertTrue(gates, "No expected-public-key gate precedes Sign with Sigul")
        for step in gates:
            self.assertIn("if: ${{ !inputs.dry-run }}", step)
            self.assertNotIn("secrets.", step)
            done = self.shell(shell_body(step), PUBLIC_KEY="", DRY_RUN="false")
            self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
            done = self.shell(
                shell_body(step),
                PUBLIC_KEY="synthetic expected public key",
                DRY_RUN="false",
            )
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_dry_runs_do_not_require_verification(self) -> None:
        self.assertIn("if: ${{ !inputs.dry-run }}", VERIFY_STEP)

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

    @unittest.expectedFailure
    def test_unverified_signature_never_reaches_the_summary(self) -> None:
        done = self.verify("sign-data", VERIFY_STATUS="7")
        self.assertEqual(done.returncode, 7, done.stdout + done.stderr)
        summary = self.root / "summary"
        text = summary.read_text() if summary.exists() else ""
        self.assertNotIn("not a PGP signature", text)

    @unittest.expectedFailure
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


if __name__ == "__main__":
    _ = unittest.main()
