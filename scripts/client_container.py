#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Pull and run the Sigul client container.

Runs on the RUNNER, under Python 3.10 or later. The container runs as
the runner's own user, with every capability dropped and no way to
gain privileges, and sees only what it needs: the credentials
directory, the scripts, and the workspace or signing repository.
Secrets reach it as files under the credentials mount, never on the
command line or in its environment.
"""

from __future__ import annotations

import os
import platform
import re
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

from action_common import ActionError, info, minimal_env
from action_inputs import Plan
from client_image import Image
from prepare_credentials import PreparedCredentials
from process_control import capture_text, kill_and_poll

CONTAINER_SCRIPTS_SOURCE = Path(__file__).resolve().parent / "container"
CONTAINER_CREDS = "/sigul-creds"
CONTAINER_REPO = "/sigul-repo"
CONTAINER_SCRIPTS = "/sigul-scripts"

# The digest 'docker pull' reports for what it pulled, on a status line
# of its own: 'Digest: sha256:<64 hex digits>'.
_PULLED_DIGEST = re.compile(r"^Digest: (sha256:[a-f0-9]{64})$", re.MULTILINE)

# Variables the docker CLI may need to reach its daemon or a private
# registry: where the caller ran 'docker login', for a bespoke image.
DOCKER_VARIABLES = (
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
)


def runner_platform() -> str:
    """Return the runner's platform, as Docker names it."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "linux/amd64"
    if machine in ("aarch64", "arm64"):
        return "linux/arm64"
    raise ActionError(f"unsupported runner architecture: {machine}")


def docker_env() -> dict[str, str]:
    """Return a clean environment for the docker CLI."""
    extra = {
        name: os.environ[name] for name in DOCKER_VARIABLES if os.environ.get(name)
    }
    return minimal_env(extra)


def docker(
    args: list[str], timeout: float | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a docker CLI command, capturing its output.

    With a timeout, a command still running when it expires is killed
    and reported as failed, so that cleanup cannot wait on a daemon
    that does not answer.
    """
    argv = ["docker", *args]
    try:
        return capture_text(argv, env=docker_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            argv, -1, "", f"docker {args[0]} did not finish within {timeout}s"
        )


@dataclass(frozen=True)
class PulledImage:
    """The image as pulled for this runner."""

    reference: str
    resolved: str
    user: str
    platform: str


def pull_image(image: Image) -> PulledImage:
    """Pull the client image for this runner's platform and inspect it.

    An image named by tag alone is pinned to the digest THIS pull
    reports, and inspected and run by that: looking the tag up again
    afterwards would let another pull or retag on a shared daemon, in
    between, put a different image in front of the credentials.
    """
    target = runner_platform()
    info(f"Pulling {image.reference} for {target}")
    done = docker(["pull", "--platform", target, image.reference])
    if done.returncode != 0:
        detail = (done.stderr or "").strip().splitlines()
        hint = (
            ". The legacy client image is published for linux/amd64 only; use an x86_64 runner"
            if image.source == "legacy" and target != "linux/amd64"
            else ""
        )
        raise ActionError(
            f"cannot pull {image.reference} for {target}: "
            + (detail[-1] if detail else "docker pull failed")
            + hint
        )
    resolved = image.reference
    if not image.has_digest:
        resolved = f"{image.reference}@{pulled_digest(image.reference, done.stdout)}"
        info(f"Resolved {image.reference} to {resolved}")
    done = docker(
        [
            "image",
            "inspect",
            "--format",
            "{{.Os}}/{{.Architecture}}|{{.Config.User}}",
            resolved,
        ]
    )
    if done.returncode != 0:
        raise ActionError(f"cannot inspect {resolved}: {done.stderr.strip()}")
    found, user = (done.stdout.strip().split("|") + [""])[:2]
    if found != target:
        raise ActionError(
            f"{image.reference} is built for {found}, but this runner is {target}"
        )
    return PulledImage(image.reference, resolved, user, target)


def pulled_digest(reference: str, pull_output: str) -> str:
    """Return the digest 'docker pull' reported for the image it pulled.

    With none reported the run fails, rather than proceed by a tag that
    can move.
    """
    found = _PULLED_DIGEST.search(pull_output)
    if found is None:
        raise ActionError(
            f"docker pull reported no digest for {reference}; refusing to run it by tag alone"
        )
    return found.group(1)


def bind(source: Path | str, target: str, readonly: bool = False) -> str:
    """Return a --mount value, quoting fields as Docker's CSV parser
    expects, so a path containing a comma cannot add a mount option."""
    fields = ["type=bind", f"source={source}", f"target={target}"]
    if readonly:
        fields.append("readonly")
    return ",".join(
        '"' + field.replace('"', '""') + '"'
        if ("," in field or '"' in field)
        else field
        for field in fields
    )


@dataclass(frozen=True)
class ContainerRun:
    """What every container run for one signing step shares."""

    plan: Plan
    pulled: PulledImage
    prepared: PreparedCredentials
    creds: Path
    name: str
    user: str
    # Whether the daemon labels containers with SELinux, in which case
    # the bind mounts need labelling disabled to be readable.
    selinux: bool = False


def daemon_security_options() -> str:
    """Return the daemon's security options, as 'docker info' lists them."""
    done = docker(["info", "--format", '{{join .SecurityOptions ","}}'])
    if done.returncode != 0:
        raise ActionError(f"cannot query the Docker daemon: {done.stderr.strip()}")
    return done.stdout


def container_user(security_options: str | None = None) -> str:
    """Return the container user that is the runner's own user on the host.

    Signatures, git objects and the credentials directory belong to the
    runner's user, so the container must run as that same user:

      * a rootful daemon shares the host's user IDs, so it is the
        runner's own UID and GID;
      * a rootless daemon maps container root to the user running it,
        so it is 0:0 -- root in name only, holding no capability;
      * a daemon with userns-remap maps every container user to a
        subordinate ID, none of them the runner's, so the container could
        neither read the credentials nor write what the workflow owns.
        That is refused, with the reason.
    """
    if security_options is None:
        security_options = daemon_security_options()
    return user_for_daemon(security_options)


def uses_selinux(security_options: str) -> bool:
    """Whether the daemon labels containers with SELinux.

    A labelled container cannot read a bind mount the host labelled for
    someone else, which is every directory the action mounts: the
    failure reads like a bad credential. global-jjb's signing job
    disabled labelling for its container for the same reason.
    """
    return "name=selinux" in security_options


def user_for_daemon(security_options: str) -> str:
    """Choose the container user from 'docker info' security options."""
    if "name=userns" in security_options:
        raise ActionError(
            "the Docker daemon remaps user namespaces (userns-remap), so no "
            + "container user is the runner's own: the client could not read "
            + "the credentials or write signatures the workflow owns. Use a "
            + "rootful or rootless daemon without userns-remap"
        )
    if "name=rootless" in security_options:
        return "0:0"
    return f"{os.getuid()}:{os.getgid()}"


def container_argv(
    run: ContainerRun,
    mounts: list[str],
    environment: dict[str, str],
    workdir: str,
    script: str,
) -> list[str]:
    """Assemble the docker run command."""
    argv = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--name",
        run.name,
        "--platform",
        run.pulled.platform,
        # The runner's own user (see container_user), so every signature
        # and git object comes out owned by the workflow, not by root.
        "--user",
        run.user,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ]
    if run.selinux:
        # The container still runs as the runner's user with every
        # capability dropped; only the mount labelling is waived.
        argv.append("--security-opt=label=disable")
    argv += [
        "--workdir",
        workdir,
        # Read-write, deliberately: NSS creates lock files beside its
        # database, and a read-only mount fails with a certificate error
        # that reads like a bad credential.
        "--mount",
        bind(run.creds, CONTAINER_CREDS),
        # sigul-conf takes the place of the image's own configuration,
        # as it did in the legacy action.
        "--mount",
        bind(run.prepared.system_config, "/etc/sigul/client.conf", readonly=True),
        "--mount",
        bind(CONTAINER_SCRIPTS_SOURCE, CONTAINER_SCRIPTS, readonly=True),
    ]
    for mount in mounts:
        argv += ["--mount", mount]
    for entry in run.plan.hosts:
        argv += ["--add-host", f"{entry.name}:{entry.address}"]
    base = {
        "HOME": run.prepared.container_home,
        "SIGUL_DEFAULT_USER": run.pulled.user,
        "SIGUL_KEY": run.plan.key_name,
        "SIGUL_PASSWORD": f"{CONTAINER_CREDS}/password",
        "MAX_RETRIES": str(run.plan.max_retries),
        "RETRY_DELAY": str(run.plan.retry_delay),
        "ATTEMPT_TIMEOUT": str(run.plan.attempt_timeout),
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for key, value in {**base, **environment}.items():
        argv += ["--env", f"{key}={value}"]
    argv += [
        "--entrypoint",
        "/bin/sh",
        # By digest wherever one is known: a tag could be moved, on a
        # reused runner, between the pull above and this run.
        run.pulled.resolved,
        f"{CONTAINER_SCRIPTS}/entrypoint.sh",
        f"{CONTAINER_SCRIPTS}/{script}",
    ]
    return argv


# How long cleanup waits on the daemon and the CLI. The runner gives a
# cancelled step about ten seconds in all -- SIGINT, then SIGTERM, then
# SIGKILL -- and the key material must be erased within them.
REMOVE_TIMEOUT_SECONDS = 5


def remove_container(name: str) -> None:
    """Remove the container, running or not, within the cleanup budget."""
    done = docker(["rm", "--force", name], timeout=REMOVE_TIMEOUT_SECONDS)
    if done.returncode and "No such container" not in done.stderr:
        raise ActionError(
            f"could not remove signing container {name}; check the daemon"
        )


def run_container(argv: list[str], name: str, timeout: int | None) -> int:
    """Run the container, streaming its output; return its status.

    The output reaches the job log with workflow commands switched off,
    under a token nothing in the container can know: a file name, or
    Sigul's own output, could otherwise start a line with '::' and
    inject a command. Whatever ends the wait -- completion, the timeout,
    or the exception a termination signal raises -- commands are
    switched back on and the CLI's group is killed without a blocking reap.
    The caller owns container removal, after erasing credential files:
    waiting on the daemon here would consume the cancellation budget
    before that erasure. No timeout can interrupt blocked kernel I/O.
    """
    token = secrets.token_hex(16)
    print(f"::stop-commands::{token}", flush=True)
    try:
        try:
            process = subprocess.Popen(argv, env=docker_env(), start_new_session=True)
        except OSError as exc:
            raise ActionError(f"cannot start the container: {exc}") from None
        try:
            return process.wait(timeout=timeout)
        except BaseException as exc:
            # Helpers can outlive an already-exited CLI; do not gate group
            # termination on the direct child's poll status.
            kill_and_poll(process)
            if isinstance(exc, subprocess.TimeoutExpired):
                raise ActionError(
                    f"container {name} did not finish within {timeout}s"
                ) from None
            raise
    finally:
        # On a line of its own: the container's last output may not end
        # with a newline, and a token joined to it would not be read as a
        # command, leaving commands switched off.
        print(f"\n::{token}::", flush=True)
