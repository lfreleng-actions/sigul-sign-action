# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Regressions at the input, logging, and container execution boundaries."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from action_common import ActionError, info
from action_inputs import build_plan
from client_container import ContainerRun, PulledImage
from prepare_credentials import PreparedCredentials
from signing import sign_data
from sigul_action import main, report_plan

from tests.helpers import PINS_DIR, REPOSITORY, base_env, scratch


class LoggingBoundaryTests(unittest.TestCase):
    def test_progress_cannot_issue_either_workflow_command_format(self) -> None:
        captured = io.StringIO()
        with redirect_stdout(captured):
            info("::add-mask::synthetic")
            info("/workspace/dist/##[add-mask]synthetic")
        for line in captured.getvalue().splitlines():
            self.assertFalse(line.lstrip().startswith("::"))
            self.assertNotIn("##[", line)

    def test_selected_filename_is_data_not_a_legacy_command(self) -> None:
        workspace = scratch(self)
        _ = (workspace / "##[stop-commands]synthetic-token").write_text("payload")
        plan = build_plan(
            base_env(workspace, SIGN_OBJECT=str(workspace), CONTAINER="modern"),
            PINS_DIR,
        )
        captured = io.StringIO()
        with redirect_stdout(captured):
            report_plan(plan)
        self.assertNotIn("##[", captured.getvalue())


class ValidationBoundaryTests(unittest.TestCase):
    def workspace(self) -> Path:
        workspace = scratch(self)
        _ = (workspace / "a.txt").write_text("payload")
        return workspace

    def test_legacy_requires_explicit_risk_acceptance(self) -> None:
        env = base_env(self.workspace())
        _ = env.pop("ALLOW_LEGACY", None)
        with self.assertRaisesRegex(ActionError, "allow-legacy"):
            _ = build_plan(env, PINS_DIR)

    def test_explicit_legacy_acceptance_preserves_protocol_selection(self) -> None:
        plan = build_plan(base_env(self.workspace(), ALLOW_LEGACY="true"), PINS_DIR)
        self.assertEqual(plan.image.source, "legacy")

    def test_rejected_inputs_emit_validation_provenance(self) -> None:
        workspace = self.workspace()
        output = workspace / "output"
        env = base_env(
            workspace,
            CONTAINER="modern",
            SIGN_TYPE="not-a-signing-operation",
            GITHUB_OUTPUT=str(output),
        )
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sigul_action.check_runtime"),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["validate"]), 1)
        self.assertTrue(output.is_file())
        self.assertEqual(output.read_text(), "validation_status=rejected\n")

    def test_successful_validation_is_distinguishable_from_later_failure(self) -> None:
        workspace = self.workspace()
        output = workspace / "output"
        env = base_env(workspace, CONTAINER="modern", GITHUB_OUTPUT=str(output))
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sigul_action.check_runtime"),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["validate"]), 0)
        self.assertTrue(output.is_file())
        self.assertEqual(output.read_text(), "validation_status=passed\n")

    def test_runtime_failure_is_not_reported_as_input_rejection(self) -> None:
        workspace = self.workspace()
        output = workspace / "output"
        with (
            mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}),
            mock.patch("sigul_action.check_runtime", side_effect=ActionError("tool")),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["validate"]), 1)
        self.assertFalse(output.exists())


class ContainerPathTests(unittest.TestCase):
    def test_relative_and_empty_image_paths_are_refused_before_execution(self) -> None:
        base = scratch(self)
        workspace = base / "workspace"
        workspace.mkdir()
        trusted = base / "bin"
        trusted.mkdir()
        (trusted / "python3").symlink_to(sys.executable)
        modules = base / "modules"
        modules.mkdir()
        _ = (modules / "client.py").write_text("")
        marker = workspace / "executed"
        payload = workspace / "python3"
        _ = payload.write_text("#!/bin/sh\nprintf 'executed' > executed\n")
        payload.chmod(0o755)
        for prefix in (".", "", "tools"):
            with self.subTest(prefix=prefix):
                done = subprocess.run(
                    [
                        "/bin/sh",
                        str(REPOSITORY / "scripts/container/entrypoint.sh"),
                        "-c",
                        "pass",
                    ],
                    cwd=workspace,
                    env={"PATH": f"{prefix}:{trusted}", "SIGULPATH": str(modules)},
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("PATH", done.stderr)
                self.assertFalse(marker.exists())


class DryRunMountTests(unittest.TestCase):
    def test_data_dry_run_mounts_workspace_read_only(self) -> None:
        workspace = scratch(self)
        _ = (workspace / "a.txt").write_text("payload")
        plan = build_plan(
            base_env(workspace, CONTAINER="modern", DRY_RUN="true"), PINS_DIR
        )
        creds = scratch(self)
        prepared = PreparedCredentials(
            creds / "client.conf", "/sigul-creds/pki", "/n", False
        )
        pulled = PulledImage("image:1", "image:1", "root", "linux/amd64")
        run = ContainerRun(plan, pulled, prepared, creds, "fixture", "1000:1000")
        commands: list[list[str]] = []

        def start(argv: list[str], _name: str, _timeout: int | None) -> int:
            commands.append(argv)
            return 0

        with mock.patch("signing.run_container", side_effect=start):
            sign_data(run)
        argv = commands[0]
        mounts = [value for value in argv if value.startswith("type=bind,")]
        workspace_mount = next(
            value for value in mounts if f"target={workspace}" in value
        )
        self.assertIn(",readonly", workspace_mount)


if __name__ == "__main__":
    _ = unittest.main()
