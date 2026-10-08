# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for scripts/sigul_action.py."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest import mock

from action_common import (
    SYSTEM_PATH,
    ActionError,
    check_trusted_location,
    set_output,
    system_tool,
)
from action_inputs import Plan, build_plan
from client_container import (
    ContainerRun,
    PulledImage,
    bind,
    container_argv,
    docker,
    pulled_digest,
    run_container,
    user_for_daemon,
)
from client_image import HostEntry
from prepare_credentials import PreparedCredentials
from signing import (
    SHARED_MEMORY,
    clear_stale_signatures,
    destroy,
    is_memory_backed,
    private_directory,
    write_manifest,
)
from sigul_action import (
    check_hosts_against_dns,
    main,
    read_handoff,
    write_handoff,
)

from tests.fake_docker_daemon import FakeDockerDaemon
from tests.helpers import PINS_DIR, REPOSITORY, base_env, scratch

SCRIPTS = REPOSITORY / "scripts"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class DaemonUserTests(unittest.TestCase):
    def user_for(self, security_options: str) -> str:
        return user_for_daemon(security_options)

    def test_rootful_daemon_runs_as_the_runner(self) -> None:
        self.assertEqual(
            self.user_for("name=seccomp,profile=builtin,name=cgroupns"),
            f"{os.getuid()}:{os.getgid()}",
        )

    def test_rootless_daemon_runs_as_container_root(self) -> None:
        self.assertEqual(
            self.user_for("name=seccomp,profile=builtin,name=rootless"), "0:0"
        )

    def test_remapped_user_namespace_is_refused(self) -> None:
        with self.assertRaises(ActionError) as caught:
            _ = self.user_for("name=seccomp,profile=builtin,name=userns")
        self.assertIn("userns-remap", str(caught.exception))


class DigestTests(unittest.TestCase):
    def test_digest_comes_from_the_pull_itself(self) -> None:
        # As 'docker pull' prints it, for a fresh pull and an existing one.
        fresh = (
            "v1: Pulling from org/client\n"
            + "5a7813e071bf: Pull complete\n"
            + f"Digest: {DIGEST_A}\n"
            + "Status: Downloaded newer image for ghcr.io/org/client:v1\n"
            + "ghcr.io/org/client:v1\n"
        )
        self.assertEqual(pulled_digest("ghcr.io/org/client:v1", fresh), DIGEST_A)
        current = (
            "3.20: Pulling from library/alpine\n"
            + f"Digest: {DIGEST_B}\n"
            + "Status: Image is up to date for alpine:3.20\n"
            + "docker.io/library/alpine:3.20\n"
        )
        self.assertEqual(pulled_digest("alpine:3.20", current), DIGEST_B)

    def test_no_digest_fails_closed(self) -> None:
        for output in ("", "docker.io/library/alpine:3.20\n", "Digest: sha256:short\n"):
            with self.subTest(output=output), self.assertRaises(ActionError):
                _ = pulled_digest("alpine:3.20", output)


def plan_for(case: unittest.TestCase, **overrides: str) -> Plan:
    root = scratch(case)
    (root / "dist").mkdir()
    for name in ("a.jar", "b.pom"):
        _ = (root / "dist" / name).write_text(name)
    return build_plan(base_env(root, SIGN_OBJECT="dist", **overrides), PINS_DIR)


class MountTests(unittest.TestCase):
    def test_plain_and_readonly(self) -> None:
        self.assertEqual(bind("/a", "/b"), "type=bind,source=/a,target=/b")
        self.assertEqual(
            bind("/a", "/b", readonly=True), "type=bind,source=/a,target=/b,readonly"
        )

    def test_a_comma_cannot_add_an_option(self) -> None:
        self.assertEqual(
            bind("/x,readonly=false,y", "/b"),
            'type=bind,"source=/x,readonly=false,y",target=/b',
        )


class ContainerCommandTests(unittest.TestCase):
    def test_assembly(self) -> None:
        plan = plan_for(
            self,
            SIGUL_IP="192.0.2.7",
            SIGUL_URI="bridge.example.org",
            SIGUL_KEY_NAME="release-key",
        )
        pulled = PulledImage("img:1", "img:1@sha256:" + "b" * 64, "", "linux/amd64")
        creds = scratch(self)
        prepared = PreparedCredentials(
            creds / "client.conf", "/sigul-creds/pki", "/sigul-creds/pki/sigul", False
        )
        argv = container_argv(
            ContainerRun(plan, pulled, prepared, creds, "sigul-sign-x", "1001:118"),
            ["type=bind,source=/w,target=/w"],
            {"MANIFEST": "/sigul-creds/manifest"},
            "/w",
            "sign_data.py",
        )
        joined = " ".join(argv)
        self.assertEqual(argv[:4], ["docker", "run", "--rm", "--pull=never"])
        self.assertIn("--user 1001:118", joined)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--security-opt=no-new-privileges", argv)
        self.assertIn("--add-host bridge.example.org:192.0.2.7", joined)
        self.assertIn(
            "type=bind,source="
            + str(creds / "client.conf")
            + ",target=/etc/sigul/client.conf,readonly",
            argv,
        )
        self.assertIn("SIGUL_PASSWORD=/sigul-creds/password", argv)
        self.assertIn("SIGUL_KEY=release-key", argv)
        self.assertIn("SIGUL_DEFAULT_USER=", argv)
        # By the digest the pull resolved, never the movable tag.
        self.assertEqual(
            argv[-3:],
            [
                pulled.resolved,
                "/sigul-scripts/entrypoint.sh",
                "/sigul-scripts/sign_data.py",
            ],
        )

    def test_no_secret_reaches_the_command_line(self) -> None:
        # Secrets travel as files under the credentials mount; the
        # command line, visible to every process, names only paths.
        plan = plan_for(self)
        pulled = PulledImage("img:1", "img:1", "root", "linux/amd64")
        creds = scratch(self)
        prepared = PreparedCredentials(
            creds / "client.conf", "/sigul-creds/pki", "/n", False
        )
        argv = container_argv(
            ContainerRun(plan, pulled, prepared, creds, "n", "0:0"),
            [],
            {},
            "/",
            "probe.py",
        )
        for name in ("SIGUL_CONF", "SIGUL_PASS", "SIGUL_PKI", "GH_KEY"):
            self.assertFalse(any(arg.startswith(name + "=") for arg in argv), name)

    def test_container_output_cannot_issue_workflow_commands(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = run_container(["true"], "not-started", 30)
        self.assertEqual(status, 0)
        lines = output.getvalue().splitlines()
        token = lines[0].removeprefix("::stop-commands::")
        self.assertEqual(len(token), 32)
        self.assertEqual(lines[-1], f"::{token}::")

    def test_restoring_commands_survives_output_without_a_newline(self) -> None:
        # The child writes to the pipe directly, so run it for real and
        # read what the runner would.
        code = (
            f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); "
            + "from client_container import run_container; "
            + "run_container(['printf', 'no newline here'], 'n', 30)"
        )
        done = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, check=True
        )
        lines = done.stdout.splitlines()
        token = lines[0].removeprefix("::stop-commands::")
        self.assertIn("no newline here", lines)
        self.assertEqual(lines[-1], f"::{token}::")

    def test_launch_failure_restores_workflow_commands(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(ActionError):
            _ = run_container(["/nonexistent/docker"], "not-started", 30)
        lines = output.getvalue().splitlines()
        token = lines[0].removeprefix("::stop-commands::")
        self.assertEqual(lines[-1], f"::{token}::")

    @unittest.skipUnless(system_tool("docker"), "needs the docker CLI, not a daemon")
    def test_a_stuck_container_is_given_up_within_the_cleanup_budget(self) -> None:
        # Whatever ends the wait, the way out must fit in the ten seconds
        # the runner allows a cancelled step, with time left to erase
        # the key material: here the CLI stands in for a container that
        # ignores its removal.
        started = time.monotonic()
        with redirect_stdout(io.StringIO()), self.assertRaises(ActionError) as caught:
            _ = run_container(["sleep", "60"], "sigul-sign-test-absent", 1)
        self.assertIn("did not finish within 1s", str(caught.exception))
        self.assertLess(time.monotonic() - started, 9)

    def test_docker_commands_in_cleanup_are_bounded(self) -> None:
        def never_returns(*_args: object, **_kwargs: object) -> object:
            raise subprocess.TimeoutExpired("docker", 5)

        with mock.patch("client_container.subprocess.run", never_returns):
            done = docker(["rm", "--force", "x"], timeout=5)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("did not finish within 5s", done.stderr)


class SigningFileTests(unittest.TestCase):
    def test_destroy_clears_read_only_trees(self) -> None:
        # A bundle as it can unpack: read-only databases in a read-only
        # directory. Cleanup runs on every exit path and must not stop.
        tree = scratch(self) / "creds"
        database = tree / "pki" / "sigul"
        database.mkdir(parents=True)
        for name in ("cert8.db", "key3.db"):
            path = database / name
            _ = path.write_bytes(b"key material")
            path.chmod(0o400)
        database.chmod(0o500)
        output = io.StringIO()
        with redirect_stdout(output):
            destroy(tree)
        self.assertFalse(tree.exists())
        self.assertEqual(output.getvalue(), "")

    def test_stale_signatures_are_cleared(self) -> None:
        plan = plan_for(self)
        for target in plan.targets:
            _ = Path(target.output).write_text("stale")
        output = io.StringIO()
        with redirect_stdout(output):
            clear_stale_signatures(plan)
        self.assertFalse(any(Path(t.output).exists() for t in plan.targets))
        self.assertIn("Removed 2 signature(s)", output.getvalue())

    def test_manifest(self) -> None:
        plan = plan_for(self)
        manifest = scratch(self) / "manifest"
        write_manifest(manifest, plan)
        fields = manifest.read_bytes().split(b"\0")
        self.assertEqual(fields[-1], b"")
        self.assertEqual(len(fields) - 1, 2 * len(plan.targets))
        self.assertEqual(fields[1], os.fsencode(plan.targets[0].output))
        self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)

    def test_outputs(self) -> None:
        path = scratch(self) / "output"
        with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(path)}):
            set_output("signed_count", "3")
            with self.assertRaises(ActionError):
                set_output("signed_count", "3\ninjected=1")
        self.assertEqual(path.read_text(), "signed_count=3\n")


class PrivateDirectoryTests(unittest.TestCase):
    def test_memory_first_where_there_is_a_tmpfs(self) -> None:
        fallback = scratch(self)
        made = private_directory("sigul-test.", str(fallback))
        self.addCleanup(shutil.rmtree, made, True)
        self.assertEqual(made.stat().st_mode & 0o777, 0o700)
        expected = (
            Path(SHARED_MEMORY)
            if is_memory_backed(SHARED_MEMORY) and os.access(SHARED_MEMORY, os.W_OK)
            else fallback
        )
        self.assertEqual(made.parent, expected)

    def test_fallback_without_a_tmpfs(self) -> None:
        fallback = scratch(self)
        with mock.patch("signing.SHARED_MEMORY", str(fallback / "no-such-shm")):
            made = private_directory("sigul-test.", str(fallback))
        self.assertEqual(made.parent, fallback)

    @unittest.skipUnless(sys.platform.startswith("linux"), "/proc/mounts is Linux-only")
    def test_mount_table_is_read_exactly(self) -> None:
        # The mount point itself, not a path beneath one, and tmpfs alone.
        self.assertFalse(is_memory_backed("/"))
        self.assertFalse(is_memory_backed(os.path.join(SHARED_MEMORY, "child")))


class HostsDnsTests(unittest.TestCase):
    def run_check(self, address: str, answer: set[str] | None) -> str:
        plan = replace(
            plan_for(self), hosts=(HostEntry("bridge.example.org", address),)
        )

        def resolve(_name: str) -> set[str]:
            if answer is None:
                raise OSError("does not resolve")
            return answer

        output = io.StringIO()
        with redirect_stdout(output):
            check_hosts_against_dns(plan, resolve)
        return output.getvalue()

    def test_matching_address_is_quiet(self) -> None:
        self.assertEqual(self.run_check("192.0.2.1", {"192.0.2.1"}), "")

    def test_stale_address_warns(self) -> None:
        self.assertIn(
            "::warning::sigul-ip 192.0.2.9", self.run_check("192.0.2.9", {"192.0.2.1"})
        )

    def test_private_name_is_explained(self) -> None:
        self.assertIn("hosts entry supplies it", self.run_check("192.0.2.9", None))


class CommandLineTests(unittest.TestCase):
    def test_usage_and_pins(self) -> None:
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["bogus"]), 2)
            self.assertEqual(main(["pin", "k8s"]), 1)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["pin", "modern"]), 0)
        self.assertIn("sigul-docker-k8s/client", output.getvalue())

    @unittest.skipUnless(sys.platform.startswith("linux"), "memfd_create is Linux-only")
    def test_handoff_round_trip(self) -> None:
        values = {
            "SIGUL_CONF": "[client]\nx: 1\n",
            "SIGUL_PASS": "p\n",
            "SIGUL_PKI": "",
            "GH_KEY": "t",
        }
        descriptor = write_handoff(values)
        # Inheritable, so it survives execve into the second stage.
        self.assertTrue(os.get_inheritable(descriptor))
        self.assertEqual(read_handoff(descriptor), values)
        # Closed once read, so no child process can inherit it.
        with self.assertRaises(OSError):
            _ = os.fstat(descriptor)


def interpreter_is_trusted() -> bool:
    """Whether check_runtime would accept the interpreter running the
    tests: a virtualenv under the developer's home is refused, as a
    planted one would be, which the test below is not about."""
    try:
        check_trusted_location(sys.executable)
    except ActionError:
        return False
    return True


@unittest.skipUnless(sys.platform.startswith("linux"), "/proc is Linux-only")
@unittest.skipUnless(system_tool("docker"), "needs the docker CLI, not a daemon")
@unittest.skipUnless(
    interpreter_is_trusted(), "the interpreter is in a writable directory"
)
class SecretEnvironmentTests(unittest.TestCase):
    def test_signing_process_is_isolated_from_the_job(self) -> None:
        """Run the real 'sign' command against a fake Docker daemon,
        which records the environment the signing process STARTED with
        -- what any same-user process can read from /proc -- and its
        open descriptors, then fails the call so nothing is pulled."""
        base = scratch(self)
        workspace = base / "workspace"
        workspace.mkdir()
        _ = (workspace / "a.txt").write_text("a")
        daemon = FakeDockerDaemon(base / "docker.sock")
        daemon.start()
        self.addCleanup(daemon.stop)
        # What an earlier step could add through GITHUB_PATH: tools that
        # would receive the credentials if the action ever ran them.
        planted = base / "planted-bin"
        planted.mkdir()
        trap = base / "planted-tool-ran"
        for tool in ("docker", "git", "gpg", "gpgconf"):
            path = planted / tool
            _ = path.write_text(f'#!/bin/sh\necho "$0" >> "{trap}"\nexit 1\n')
            path.chmod(0o755)
        secrets = {
            "SIGUL_CONF": "conf-secret-value",
            "SIGUL_PASS": "pass-secret-value",
            "SIGUL_PKI": "pki-secret-value",
            "GH_KEY": "token-secret-value",
        }
        # What else a job's environment carries, none of it the
        # signing process's business.
        others = {
            "ACTIONS_RUNTIME_TOKEN": "runtime-token-value",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-token-value",
            "JOB_LEVEL_SECRET": "job-secret-value",
            "GITHUB_ENV": str(base / "github-env"),
        }
        env = dict(
            base_env(workspace, SIGN_OBJECT="a.txt", DRY_RUN="true"),
            PATH=f"{planted}{os.pathsep}{os.environ['PATH']}",
            DOCKER_HOST=daemon.url,
            RUNNER_TEMP=str(base),
            **secrets,
            **others,
        )
        for flag in (
            "HAVE_SIGUL_CONF",
            "HAVE_SIGUL_PASS",
            "HAVE_SIGUL_PKI",
            "HAVE_GH_KEY",
        ):
            del env[flag]
        done = subprocess.run(
            [sys.executable, "-E", "-s", str(SCRIPTS / "sigul_action.py"), "sign"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        # Stopped at the daemon: older CLIs fail 'docker info' on the
        # error the fake daemon returns, newer ones the pull after it.
        self.assertRegex(done.stdout, r"cannot (query the Docker daemon|pull )")
        # The real CLI from the system's directories reached the daemon;
        # nothing planted earlier on PATH ever ran.
        self.assertTrue(daemon.environments, "the docker CLI never called")
        self.assertFalse(trap.exists(), trap.read_text() if trap.exists() else "")
        for recorded in daemon.environments:
            variables = dict(
                entry.split(b"=", 1) for entry in recorded.split(b"\0") if b"=" in entry
            )
            self.assertEqual(variables.get(b"HAVE_SIGUL_CONF"), b"true")
            self.assertEqual(variables.get(b"PATH"), SYSTEM_PATH.encode())
            for value in [*secrets.values(), *others.values()]:
                self.assertNotIn(value.encode(), recorded)
        # The handoff was read and closed before anything was started.
        self.assertFalse(any("sigul-handoff" in d for d in daemon.descriptors))
        self.assertEqual(sorted(p.name for p in base.glob("sigul*")), [])


if __name__ == "__main__":
    _ = unittest.main()
