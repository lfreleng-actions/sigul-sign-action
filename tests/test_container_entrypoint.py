# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/container/entrypoint.sh, run with the host's shell.

The entrypoint chooses the image's interpreter by trying to import
Sigul's client module. These tests stand a fake SIGULPATH in for the
image's, so the choice can be exercised without a container, and give
'python3' and 'python' different behaviour, so that the interpreter
the probe chose can be told from the one the fallback would have.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from tests.helpers import REPOSITORY, scratch

ENTRYPOINT = REPOSITORY / "scripts" / "container" / "entrypoint.sh"
SHELL = shutil.which("sh") or "/bin/sh"

# Records that it was imported, as a module left at the workspace root
# by a project or an earlier step would be free to do anything.
PLANTED = (
    "import os\n"
    "here = os.path.dirname(os.path.abspath(__file__))\n"
    'open(os.path.join(here, "planted-module-ran"), "a").write(__name__ + "\\n")\n'
)

# Stands in for an interpreter that cannot import Sigul, whatever it is
# asked: the first candidate, which the fallback would pick.
FAKE_PYTHON3 = "#!/bin/sh\necho fake\nexit 7\n"


@unittest.skipUnless(shutil.which("sh"), "needs a POSIX shell")
class EntrypointTests(unittest.TestCase):
    def run_entrypoint(
        self, workdir: Path, sigulpath: Path, *args: str
    ) -> subprocess.CompletedProcess[str]:
        """Run the entrypoint where 'python3' is a fake that cannot import
        anything and 'python' is the interpreter running the tests."""
        bin_dir = scratch(self) / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "python3"
        _ = fake.write_text(FAKE_PYTHON3)
        fake.chmod(0o755)
        (bin_dir / "python").symlink_to(sys.executable)
        env = {
            "PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin",
            "SIGULPATH": str(sigulpath),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return subprocess.run(
            [SHELL, str(ENTRYPOINT), *args],
            cwd=workdir,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_prefers_the_interpreter_that_imports_sigul(self) -> None:
        # Only 'python' can import client from SIGULPATH, and it comes
        # second: choosing it proves the probe consulted SIGULPATH rather
        # than falling back to the first interpreter found.
        base = scratch(self)
        sigulpath = base / "sigul"
        sigulpath.mkdir()
        _ = (sigulpath / "client.py").write_text("")
        done = self.run_entrypoint(base, sigulpath, "-c", "print('ran')")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "ran")

    def test_falls_back_to_the_first_interpreter_without_sigul(self) -> None:
        base = scratch(self)
        empty = base / "nothing"
        empty.mkdir()
        done = self.run_entrypoint(base, empty, "-c", "print('ran')")
        self.assertEqual(done.returncode, 7)
        self.assertEqual(done.stdout.strip(), "fake")

    def test_never_imports_a_module_from_the_working_directory(self) -> None:
        # The working directory is the workspace for sign-data. Sigul's
        # module names there must neither be run by the probe nor make
        # the probe believe an interpreter has Sigul: with nothing on
        # SIGULPATH, the fallback must still win.
        base = scratch(self)
        workspace = base / "workspace"
        workspace.mkdir()
        for name in ("client", "utils", "settings"):
            _ = (workspace / f"{name}.py").write_text(PLANTED)
        empty = base / "nothing"
        empty.mkdir()
        done = self.run_entrypoint(workspace, empty, "-c", "print('ran')")
        self.assertEqual(done.returncode, 7, done.stdout + done.stderr)
        marker = workspace / "planted-module-ran"
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")

    def test_no_interpreter_is_an_error(self) -> None:
        base = scratch(self)
        done = subprocess.run(
            [SHELL, str(ENTRYPOINT), "-c", "pass"],
            cwd=base,
            env={"PATH": str(base / "empty-bin"), "SIGULPATH": str(base)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 127)
        self.assertIn("no Python interpreter", done.stderr)


if __name__ == "__main__":
    _ = unittest.main()
