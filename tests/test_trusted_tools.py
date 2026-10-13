# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Regressions for Copilot 4224956809 and 4224956833.

Run on Linux as root to isolate file, directory and symlink permissions:
only new fixture paths are chowned, and non-root checks run as UID 501.
Ordinary non-root runs reproduce the owner-writable file bug too. These
checks are defence in depth within a trusted job, not step isolation.
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from action_common import is_untrusted_directory

from tests.helpers import REPOSITORY


class TrustFixture:
    """Run the real gates with disposable files and no inherited secrets."""

    def __init__(self, case: unittest.TestCase) -> None:
        self.case: unittest.TestCase = case
        self.job_uid: int = 501 if os.geteuid() == 0 else os.geteuid()
        # /tmp is itself replaceable. Root fixtures need a protected
        # ancestry so rejecting an ancestor cannot hide a missing file check.
        parent = "/" if os.geteuid() == 0 else "/tmp"
        self.base: Path = Path(
            tempfile.mkdtemp(prefix="sigul-trust.", dir=parent)
        ).resolve()
        case.addCleanup(shutil.rmtree, self.base)
        self.base.chmod(0o755)
        witness = self.base / "witness"
        witness.mkdir()
        if os.geteuid() == 0:
            os.chown(witness, self.job_uid, -1)
        self.marker: Path = witness / "executed"
        # Root runs drop checks to job_uid, which cannot traverse a private
        # checkout: a GitHub runner's home is mode 0750. Run the real gate
        # code from a readable copy inside the fixture instead.
        code = self.base / "code"
        code.mkdir()
        code.chmod(0o755)
        for name in ("action_common.py", "trusted_interpreter.sh"):
            copied = code / name
            _ = shutil.copyfile(REPOSITORY / "scripts" / name, copied)
            copied.chmod(0o644)
        self.scripts: Path = code
        self.gate: Path = code / "trusted_interpreter.sh"

    def tool(
        self,
        relative: str = "bin/python3",
        *,
        mode: int = 0o755,
        owner: int | None = None,
        directory_mode: int = 0o555,
    ) -> Path:
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o755)
        self.case.addCleanup(path.parent.chmod, 0o755)
        _ = path.write_text('#!/bin/sh\nprintf "executed\\n" > "$TRUST_TEST_MARKER"\n')
        path.chmod(mode)
        if os.geteuid() == 0:
            os.chown(path, self.job_uid if owner is None else owner, -1)
        path.parent.chmod(directory_mode)
        return path

    def link(self, target: Path, relative: str = "bin/python3") -> Path:
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
        path.parent.chmod(0o555)
        self.case.addCleanup(path.parent.chmod, 0o755)
        return path

    def run_as(
        self,
        argv: list[str],
        *,
        uid: int | None = None,
        search_path: str = "/usr/bin:/bin",
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        selected_uid = self.job_uid if uid is None else uid
        return subprocess.run(
            argv,
            env={
                "PATH": search_path,
                "LANG": "C",
                "LC_ALL": "C",
                "TRUST_TEST_MARKER": str(self.marker),
                **(extra_env or {}),
            },
            user=selected_uid if os.geteuid() == 0 else None,
            group=selected_uid if os.geteuid() == 0 else None,
            extra_groups=[] if os.geteuid() == 0 else None,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def python_check(
        self, tool: Path | str, *, uid: int | None = None
    ) -> subprocess.CompletedProcess[str]:
        # This is the test runner's interpreter, never the candidate.
        code = (
            "import sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from action_common import ActionError, check_trusted_location\n"
            "try:\n"
            "    check_trusted_location(sys.argv[2])\n"
            "except ActionError as error:\n"
            "    print(error)\n"
            "    sys.exit(42)\n"
        )
        return self.run_as(
            [
                sys.executable,
                "-B",
                "-E",
                "-s",
                "-c",
                code,
                str(self.scripts),
                str(tool),
            ],
            uid=uid,
        )

    def shell_check(
        self,
        tool: Path,
        *,
        uid: int | None = None,
        search_path: str | None = None,
        gate: Path | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        script = (
            'set -euo pipefail; source "$1"; '
            "trusted_python3 || exit 1; "
            'printf "selected=%s\\n" "$TRUSTED_PYTHON3"; '
            '"$TRUSTED_PYTHON3" -E -s -c "pass"'
        )
        return self.run_as(
            [
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                script,
                "trust-test",
                str(gate if gate is not None else self.gate),
            ],
            uid=uid,
            search_path=str(tool.parent) if search_path is None else search_path,
            extra_env=extra_env,
        )

    def assert_python_refused(self, done: subprocess.CompletedProcess[str]) -> None:
        # An import error or uncaught OSError must not count as a refusal.
        self.case.assertEqual(done.returncode, 42, done.stdout + done.stderr)

    def assert_shell_refused(self, done: subprocess.CompletedProcess[str]) -> None:
        # Check the witness first: a gate must not run Python to decide
        # whether that same Python is safe, even if it subsequently fails.
        self.case.assertFalse(self.marker.exists(), "the planted interpreter ran")
        self.case.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.case.assertIn("::error::", done.stdout)

    def system_python(self) -> Path:
        tool = Path("/usr/bin/python3")
        if not tool.is_file():
            self.case.skipTest("needs the distribution's /usr/bin/python3")
        resolved = tool.resolve(strict=True)
        self.case.assertTrue(stat.S_ISREG(resolved.stat().st_mode))
        self.case.assertTrue(os.access(resolved, os.X_OK))
        for path in {tool, resolved, *tool.parents, *resolved.parents}:
            status = path.stat()
            self.case.assertEqual(status.st_uid, 0, str(path))
            self.case.assertFalse(status.st_mode & 0o022, str(path))
        return tool

    def instrumented_gate(self) -> Path:
        """Redirect only literal helper paths in a disposable copy of the gate."""
        script = (REPOSITORY / "scripts/trusted_interpreter.sh").read_text()
        helpers = self.base / "coreutils"
        helpers.mkdir()
        for name in ("stat", "readlink"):
            wrapper = helpers / name
            called = shlex.quote(str(self.marker.parent / f"{name}-called"))
            leaked = shlex.quote(str(self.marker.parent / "leaked"))
            _ = wrapper.write_text(
                "#!/bin/bash\n"
                + f"printf called >> {called}\n"
                + "if [[ -v SIGUL_PASS || -v TRUST_TEST_SECRET || -v TRUST_TEST_MARKER ]]; then\n"
                + f"    printf leaked > {leaked}\n"
                + "fi\n"
                + f'exec -c /usr/bin/{name} "$@"\n'
            )
            wrapper.chmod(0o755)
            script = script.replace(f"/usr/bin/{name}", str(wrapper))
        copied = self.base / "trusted_interpreter.sh"
        _ = copied.write_text(script)
        return copied

    def replaceable_ancestor(self) -> Path:
        tool = self.tool("replaceable/bin/python3", owner=0)
        tool.parent.parent.chmod(0o777)
        return tool

    def replaceable_symlink_chain(self) -> Path:
        middle = self.link(self.system_python(), "redirect/python3")
        middle.parent.chmod(0o777)
        return self.link(middle)

    def owner_changeable_directory(self) -> Path:
        tool = self.link(self.system_python())
        os.chown(tool.parent, self.job_uid, -1)
        return tool


class PythonTrustedToolTests(unittest.TestCase):
    def test_nonroot_writable_file_in_readonly_parent_is_refused(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool()
        self.assertEqual(tool.stat().st_uid, fixture.job_uid)
        self.assertEqual(stat.S_IMODE(tool.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(tool.parent.stat().st_mode), 0o555)
        fixture.assert_python_refused(fixture.python_check(tool))

    def test_nonroot_self_owned_readonly_file_is_refused(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_python_refused(fixture.python_check(fixture.tool(mode=0o555)))

    def test_nonroot_writable_resolved_file_is_refused(self) -> None:
        fixture = TrustFixture(self)
        target = fixture.tool("target/python3")
        fixture.assert_python_refused(fixture.python_check(fixture.link(target)))

    @unittest.skipIf(os.geteuid() == 0, "requires a non-root owner")
    def test_self_owned_readonly_directory_is_untrusted(self) -> None:
        fixture = TrustFixture(self)
        directory = fixture.tool().parent
        self.assertFalse(os.access(directory, os.W_OK))
        self.assertEqual(directory.stat().st_uid, os.geteuid())
        self.assertTrue(is_untrusted_directory(str(directory)))

    def test_nonexecutable_regular_file_is_refused(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(mode=0o644, owner=0)
        fixture.assert_python_refused(fixture.python_check(tool))

    def test_directory_is_not_an_executable_file(self) -> None:
        fixture = TrustFixture(self)
        directory = fixture.tool(owner=0).with_name("directory")
        directory.parent.chmod(0o755)
        directory.mkdir()
        directory.parent.chmod(0o555)
        fixture.assert_python_refused(fixture.python_check(directory))

    def test_missing_file_is_refused(self) -> None:
        fixture = TrustFixture(self)
        missing = fixture.tool(owner=0).with_name("missing")
        fixture.assert_python_refused(fixture.python_check(missing))

    def test_actual_root_owned_system_python_is_accepted(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.system_python()
        uids = (0, fixture.job_uid) if os.geteuid() == 0 else (fixture.job_uid,)
        for uid in uids:
            with self.subTest(uid=uid):
                done = fixture.python_check(tool, uid=uid)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


@unittest.skipUnless(sys.platform.startswith("linux"), "needs Linux and GNU coreutils")
class ShellTrustedToolTests(unittest.TestCase):
    def test_nonroot_writable_file_is_refused_before_execution(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_shell_refused(fixture.shell_check(fixture.tool()))

    def test_nonroot_self_owned_readonly_file_is_refused_before_execution(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_shell_refused(fixture.shell_check(fixture.tool(mode=0o555)))

    def test_nonroot_writable_resolved_file_is_refused_before_execution(self) -> None:
        fixture = TrustFixture(self)
        target = fixture.tool("target/python3")
        fixture.assert_shell_refused(fixture.shell_check(fixture.link(target)))

    def test_writable_resolved_parent_is_refused_before_execution(self) -> None:
        fixture = TrustFixture(self)
        target = fixture.tool("target/python3", owner=0, directory_mode=0o777)
        fixture.assert_shell_refused(fixture.shell_check(fixture.link(target)))

    def test_nonexecutable_file_is_refused_without_running_it(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_shell_refused(fixture.shell_check(fixture.tool(mode=0o644)))

    def test_world_writable_parent_is_refused_before_execution(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(directory_mode=0o777)
        uids = (0, fixture.job_uid) if os.geteuid() == 0 else (fixture.job_uid,)
        for uid in uids:
            with self.subTest(uid=uid):
                fixture.assert_shell_refused(fixture.shell_check(tool, uid=uid))

    def test_actual_root_owned_system_python_is_accepted(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.system_python()
        uids = (0, fixture.job_uid) if os.geteuid() == 0 else (fixture.job_uid,)
        for uid in uids:
            with self.subTest(uid=uid):
                done = fixture.shell_check(tool, uid=uid)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.stdout, f"selected={tool.resolve(strict=True)}\n")
                self.assertFalse(fixture.marker.exists())

    def test_refusal_clears_a_previously_selected_interpreter(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool()
        script = (
            'set -euo pipefail; source "$1"; TRUSTED_PYTHON3=stale; '
            'if trusted_python3; then exit 7; fi; [[ -z "$TRUSTED_PYTHON3" ]]'
        )
        done = fixture.run_as(
            [
                "/bin/bash",
                "-c",
                script,
                "trust-test",
                str(fixture.gate),
            ],
            search_path=str(tool.parent),
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("::error::refusing", done.stdout)
        self.assertFalse(fixture.marker.exists())

    def test_path_helpers_are_not_used_to_validate_a_safe_interpreter(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.system_python()
        for name in ("stat", "readlink", "id", "dirname"):
            _ = fixture.tool(f"helpers/{name}")
        search_path = f"{fixture.base}/helpers:/usr/bin:/bin"
        uids = (0, fixture.job_uid) if os.geteuid() == 0 else (fixture.job_uid,)
        for uid in uids:
            with self.subTest(uid=uid):
                done = fixture.shell_check(tool, uid=uid, search_path=search_path)
                self.assertFalse(fixture.marker.exists(), "a PATH helper ran")
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.stdout, f"selected={tool.resolve(strict=True)}\n")


@unittest.skipUnless(
    sys.platform.startswith("linux") and os.geteuid() == 0,
    "needs root on Linux to create isolated ownership fixtures and drop to UID 501",
)
class RootTrustPolicyTests(unittest.TestCase):
    def test_python_nonroot_refuses_other_user_readonly_file(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=502, mode=0o555)
        fixture.assert_python_refused(fixture.python_check(tool))

    def test_shell_nonroot_refuses_other_user_readonly_file(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=502, mode=0o555)
        fixture.assert_shell_refused(fixture.shell_check(tool))

    def test_python_nonroot_refuses_other_user_readonly_directory(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, mode=0o555)
        os.chown(tool.parent, 502, -1)
        fixture.assert_python_refused(fixture.python_check(tool))

    def test_shell_nonroot_refuses_other_user_readonly_directory(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, mode=0o555)
        os.chown(tool.parent, 502, -1)
        fixture.assert_shell_refused(fixture.shell_check(tool))

    def test_python_nonroot_refuses_other_user_symlink(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.link(fixture.system_python())
        os.chown(tool, 502, -1, follow_symlinks=False)
        fixture.assert_python_refused(fixture.python_check(tool))

    def test_shell_nonroot_refuses_other_user_symlink(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.link(fixture.system_python())
        os.chown(tool, 502, -1, follow_symlinks=False)
        fixture.assert_shell_refused(fixture.shell_check(tool))

    def test_python_root_refuses_nonroot_owned_readonly_file(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_python_refused(
            fixture.python_check(fixture.tool(mode=0o555), uid=0)
        )

    def test_shell_root_refuses_nonroot_owned_readonly_file(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_shell_refused(
            fixture.shell_check(fixture.tool(mode=0o555), uid=0)
        )

    def test_python_root_refuses_group_writable_file(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, mode=0o775)
        fixture.assert_python_refused(fixture.python_check(tool, uid=0))

    def test_shell_root_refuses_group_writable_file(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, mode=0o775)
        fixture.assert_shell_refused(fixture.shell_check(tool, uid=0))

    def test_python_nonroot_refuses_file_writable_by_another_group(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, mode=0o775)
        fixture.assert_python_refused(fixture.python_check(tool))

    def test_shell_nonroot_refuses_file_writable_by_another_group(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, mode=0o775)
        fixture.assert_shell_refused(fixture.shell_check(tool))

    def test_python_root_refuses_world_writable_file(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, mode=0o757)
        fixture.assert_python_refused(fixture.python_check(tool, uid=0))

    def test_shell_root_refuses_world_writable_file(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, mode=0o757)
        fixture.assert_shell_refused(fixture.shell_check(tool, uid=0))

    def test_root_considers_nonroot_owned_readonly_directory_untrusted(self) -> None:
        fixture = TrustFixture(self)
        directory = fixture.owner_changeable_directory().parent
        self.assertTrue(is_untrusted_directory(str(directory)))

    def test_shell_root_refuses_nonroot_owned_readonly_directory(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.owner_changeable_directory()
        fixture.assert_shell_refused(fixture.shell_check(tool, uid=0))

    def test_root_considers_group_writable_directory_untrusted(self) -> None:
        fixture = TrustFixture(self)
        directory = fixture.tool(owner=0, directory_mode=0o775).parent
        self.assertTrue(is_untrusted_directory(str(directory)))

    def test_shell_root_refuses_group_writable_directory(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, directory_mode=0o775)
        fixture.assert_shell_refused(fixture.shell_check(tool, uid=0))

    def test_python_nonroot_refuses_directory_writable_by_another_group(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, directory_mode=0o775)
        fixture.assert_python_refused(fixture.python_check(tool))

    def test_shell_nonroot_refuses_directory_writable_by_another_group(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.tool(owner=0, directory_mode=0o775)
        fixture.assert_shell_refused(fixture.shell_check(tool))

    def test_python_nonroot_refuses_self_owned_readonly_parent_of_safe_tool(
        self,
    ) -> None:
        fixture = TrustFixture(self)
        fixture.assert_python_refused(
            fixture.python_check(fixture.owner_changeable_directory())
        )

    def test_shell_nonroot_refuses_self_owned_readonly_parent_of_safe_tool(
        self,
    ) -> None:
        fixture = TrustFixture(self)
        fixture.assert_shell_refused(
            fixture.shell_check(fixture.owner_changeable_directory())
        )

    def test_python_refuses_replaceable_ancestor_above_readonly_parent(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_python_refused(
            fixture.python_check(fixture.replaceable_ancestor())
        )

    def test_shell_refuses_replaceable_ancestor_above_readonly_parent(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_shell_refused(
            fixture.shell_check(fixture.replaceable_ancestor())
        )

    def test_python_refuses_replaceable_intermediate_symlink_location(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_python_refused(
            fixture.python_check(fixture.replaceable_symlink_chain())
        )

    def test_shell_refuses_replaceable_intermediate_symlink_location(self) -> None:
        fixture = TrustFixture(self)
        fixture.assert_shell_refused(
            fixture.shell_check(fixture.replaceable_symlink_chain())
        )

    def test_protected_relative_symlink_chain_is_accepted(self) -> None:
        fixture = TrustFixture(self)
        target = fixture.system_python()
        _ = fixture.link(target, "target/python3")
        candidate = fixture.link(Path("../target/python3"))
        for uid in (0, fixture.job_uid):
            with self.subTest(uid=uid):
                python = fixture.python_check(candidate, uid=uid)
                self.assertEqual(python.returncode, 0, python.stdout + python.stderr)
                shell = fixture.shell_check(candidate, uid=uid)
                self.assertEqual(shell.returncode, 0, shell.stdout + shell.stderr)
                self.assertEqual(
                    shell.stdout, f"selected={target.resolve(strict=True)}\n"
                )

    def test_parent_component_is_resolved_after_the_symlink(self) -> None:
        fixture = TrustFixture(self)
        target = fixture.system_python()
        leaf = fixture.base / "real/leaf"
        leaf.mkdir(parents=True)
        (leaf.parent / "python3").symlink_to(target)
        (fixture.base / "alias").symlink_to(leaf)
        candidate = fixture.base / "alias/../python3"
        python = fixture.python_check(candidate)
        self.assertEqual(python.returncode, 0, python.stdout + python.stderr)
        shell = fixture.shell_check(candidate)
        self.assertEqual(shell.returncode, 0, shell.stdout + shell.stderr)
        self.assertEqual(shell.stdout, f"selected={target.resolve(strict=True)}\n")
        # '..' must not erase the requirement to trust the directory visited.
        leaf.chmod(0o777)
        fixture.assert_python_refused(fixture.python_check(candidate))
        fixture.assert_shell_refused(fixture.shell_check(candidate))

    def test_link_target_with_trailing_newline_is_not_truncated(self) -> None:
        fixture = TrustFixture(self)
        target = fixture.system_python()
        directory = fixture.base / "target\n"
        directory.mkdir()
        (directory / "python3").symlink_to(target)
        (fixture.base / "bin").symlink_to(directory)
        candidate = fixture.base / "bin/python3"
        python = fixture.python_check(candidate)
        self.assertEqual(python.returncode, 0, python.stdout + python.stderr)
        shell = fixture.shell_check(candidate)
        self.assertEqual(shell.returncode, 0, shell.stdout + shell.stderr)
        self.assertEqual(shell.stdout, f"selected={target.resolve(strict=True)}\n")

    def test_symlink_hop_bound_accepts_40_and_refuses_41(self) -> None:
        for count in (40, 41):
            with self.subTest(hops=count):
                fixture = TrustFixture(self)
                target = fixture.system_python().resolve(strict=True)
                directory = fixture.base / "bin"
                directory.mkdir()
                for index in range(count):
                    name = "python3" if index == 0 else f"link-{index}"
                    destination = (
                        target if index == count - 1 else Path(f"link-{index + 1}")
                    )
                    (directory / name).symlink_to(destination)
                candidate = directory / "python3"
                python = fixture.python_check(candidate)
                shell = fixture.shell_check(candidate)
                if count == 40:
                    self.assertEqual(
                        python.returncode, 0, python.stdout + python.stderr
                    )
                    self.assertEqual(shell.returncode, 0, shell.stdout + shell.stderr)
                    self.assertEqual(shell.stdout, f"selected={target}\n")
                else:
                    fixture.assert_python_refused(python)
                    fixture.assert_shell_refused(shell)

    def test_component_walk_is_bounded(self) -> None:
        fixture = TrustFixture(self)
        tool = fixture.system_python()
        directory = f"{tool.parent}/" + "./" * 256
        fixture.assert_python_refused(fixture.python_check(directory + tool.name))
        fixture.assert_shell_refused(fixture.shell_check(tool, search_path=directory))

    def test_coreutils_never_receive_the_signing_environment(self) -> None:
        fixture = TrustFixture(self)
        gate = fixture.instrumented_gate()
        tool = fixture.system_python()
        # Start as the witness directory's owner so root can append later.
        for uid in (fixture.job_uid, 0):
            with self.subTest(uid=uid):
                done = fixture.shell_check(
                    tool,
                    uid=uid,
                    gate=gate,
                    extra_env={
                        "SIGUL_PASS": "synthetic-pass",
                        "TRUST_TEST_SECRET": "synthetic-input",
                    },
                )
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.stdout, f"selected={tool.resolve(strict=True)}\n")
                self.assertTrue((fixture.marker.parent / "stat-called").exists())
                self.assertTrue((fixture.marker.parent / "readlink-called").exists())
                self.assertFalse((fixture.marker.parent / "leaked").exists())

    def test_nonroot_bootstraps_helpers_before_executing_them(self) -> None:
        for unsafe in ("owner", "writable", "symlink", "parent"):
            with self.subTest(unsafe=unsafe):
                fixture = TrustFixture(self)
                gate = fixture.instrumented_gate()
                helper = fixture.base / "coreutils/stat"
                if unsafe == "owner":
                    helper.chmod(0o555)
                    os.chown(helper, fixture.job_uid, -1)
                elif unsafe == "writable":
                    helper.chmod(0o777)
                elif unsafe == "symlink":
                    helper.unlink()
                    helper.symlink_to("/usr/bin/stat")
                else:
                    helper.parent.chmod(0o555)
                    os.chown(helper.parent, fixture.job_uid, -1)
                fixture.assert_shell_refused(
                    fixture.shell_check(fixture.system_python(), gate=gate)
                )
                self.assertFalse((fixture.marker.parent / "stat-called").exists())
                self.assertFalse((fixture.marker.parent / "readlink-called").exists())


if __name__ == "__main__":
    _ = unittest.main()
