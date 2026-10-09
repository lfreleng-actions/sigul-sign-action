#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The action's entry point: 'validate', then 'sign'.

Runs on the RUNNER, under Python 3.10 or later, invoked by action.yaml
as 'python3 -E -s sigul_action.py <command>' so that no PYTHON*
variable from the job can change what it imports.

  validate  Checks public input structure and credential presence,
            emits validation provenance, and prints the plan without
            receiving signing credential values.
  sign      Re-executes without the secret inputs in its environment,
            rebuilds the same plan, and signs (signing.py).
  pin NAME  Prints the image reference a built-in container pins; the
            tests use it so that they exercise exactly what callers get.
"""

from __future__ import annotations

import os
import signal
import socket
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from action_common import (
    PASSTHROUGH_VARIABLES,
    SYSTEM_PATH,
    ActionError,
    check_trusted_location,
    error,
    info,
    notice,
    set_output,
    system_tool,
    warning,
)
from action_inputs import Plan, build_plan
from client_container import DOCKER_VARIABLES
from client_image import NICKNAMES, read_pin
from signing import sign
from termination import Cancelled as Cancelled
from termination import on_signal as on_signal

PINS_DIR = Path(__file__).resolve().parent.parent / "containers"

# How many files the log lists by name before counting the rest.
LISTING_LIMIT = 50

# The secret inputs. Handed to a fresh process image through an
# anonymous in-memory file, so that neither this process nor any child
# -- docker, git, gpg -- carries them in its environment; see
# command_sign().
SECRET_INPUTS = ("SIGUL_CONF", "SIGUL_PASS", "SIGUL_PKI", "GH_KEY")

# All the signing process keeps of the environment it is given. Like
# lfit/sigul-sign-action 2.0.0's allowlist, this drops every other
# variable: workflow-level secrets, runner credentials such as
# ACTIONS_RUNTIME_TOKEN and ACTIONS_ID_TOKEN_REQUEST_TOKEN, and
# GITHUB_ENV and GITHUB_PATH, which would let it change later steps.
SIGNING_ENVIRONMENT = (
    # The plan's inputs, as action.yaml names them.
    "SIGN_TYPE",
    "SIGN_OBJECT",
    "SIGUL_IP",
    "SIGUL_URI",
    "EXPECTED_BRIDGE",
    "SIGUL_KEY_NAME",
    "GH_USER",
    "CONTAINER",
    "ALLOW_LEGACY",
    "CONTAINER_IMAGE",
    "CONTAINER_TAG",
    "CONTAINER_DIGEST",
    "HOSTS_ENTRY",
    "PUSH_TAG",
    "DRY_RUN",
    "EXCLUDE_GLOBS",
    "MAX_RETRIES",
    "RETRY_DELAY",
    "ATTEMPT_TIMEOUT",
    # Where to sign and report, and against which repository.
    "GITHUB_WORKSPACE",
    "GITHUB_REPOSITORY",
    "GITHUB_SERVER_URL",
    "GITHUB_ACTOR",
    "GITHUB_OUTPUT",
    "GITHUB_STEP_SUMMARY",
    "RUNNER_OS",
    "RUNNER_TEMP",
    # Reaching the Docker daemon, a rootless one included, and the
    # registry logins a bespoke image may need. PATH is not carried
    # over: the new image gets SYSTEM_PATH, never the job's.
    "HOME",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    *DOCKER_VARIABLES,
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    *PASSTHROUGH_VARIABLES,
)


# --- Validation ------------------------------------------------------


def check_runtime() -> None:
    """Fail early, with the reason, where the action cannot run.

    Every tool is looked up in SYSTEM_PATH and refused where an earlier
    step of the job could have planted it (see action_common.SYSTEM_PATH),
    gpgconf included, because the cleanup that runs it must never fail
    part-way. The shell checked the interpreter file and its complete
    path before executing it (scripts/trusted_interpreter.sh). Repeat
    that policy here and apply it to the other primary runner tools.
    """
    runner_os = os.environ.get("RUNNER_OS", "Linux")
    if runner_os != "Linux":
        raise ActionError(f"this action needs a Linux runner (this one is {runner_os})")
    if sys.executable:
        check_trusted_location(sys.executable)
    for tool in ("docker", "git", "gpg"):
        found = system_tool(tool)
        if found is None:
            raise ActionError(
                f"{tool} is not installed in the runner's system directories ({SYSTEM_PATH})"
            )
        check_trusted_location(found)
    gpgconf = system_tool("gpgconf")
    if gpgconf is not None:
        check_trusted_location(gpgconf)


def report_plan(plan: Plan) -> None:
    """Print the plan and its annotations."""
    for message in plan.messages.notices:
        notice(message)
    for message in plan.messages.warnings:
        warning(message)
    info(f"Container: {plan.image.source} ({plan.image.reference})")
    for entry in plan.hosts:
        info(f"Hosts entry: {entry.address} {entry.name}")
    if plan.sign_type == "sign-data":
        info(f"Files to sign: {len(plan.targets)}")
        # A Maven repository runs to thousands; the log is for reading.
        for target in plan.targets[:LISTING_LIMIT]:
            info(f"  {target.name}")
        if len(plan.targets) > LISTING_LIMIT:
            info(f"  … and {len(plan.targets) - LISTING_LIMIT} more")
    else:
        action = "sign and push" if plan.push_tag else "sign"
        info(f"Tag to {action}: {plan.tag}")
    if plan.dry_run:
        info("Dry run: checks everything, signs nothing")


def resolve_host(name: str) -> set[str]:
    """Return the addresses DNS gives for a host name."""
    return {str(item[4][0]) for item in socket.getaddrinfo(name, None)}


def check_hosts_against_dns(
    plan: Plan, resolve: Callable[[str], set[str]] | None = None
) -> None:
    """Warn when a hosts entry overrides a different DNS answer.

    A hosts entry pins the bridge to one address inside the container.
    Where public DNS gives other addresses, the pinned one may be stale
    -- as several projects' SIGUL_BRIDGE_IP values now are -- and
    signing would then go nowhere.
    """
    lookup = resolve or resolve_host
    for entry in plan.hosts:
        try:
            found = lookup(entry.name)
        except OSError:
            info(f"{entry.name} does not resolve here; the hosts entry supplies it")
            continue
        if entry.address not in found:
            warning(
                f"sigul-ip {entry.address} is not an address DNS gives for "
                + f"{entry.name} ({', '.join(sorted(found))}). The hosts entry "
                + "overrides DNS in the container, so if signing cannot reach "
                + "the bridge, the address is probably stale"
            )


# --- Commands --------------------------------------------------------


def command_validate() -> None:
    check_runtime()
    try:
        plan = build_plan(os.environ, PINS_DIR)
    except ActionError:
        set_output("validation_status", "rejected")
        raise
    set_output("validation_status", "passed")
    report_plan(plan)
    check_hosts_against_dns(plan)
    info("Inputs validated ✅")


def command_sign() -> None:
    """Hand the secrets over to a fresh process image, then sign.

    The secret inputs arrive in this process's environment. Removing
    them from os.environ is not enough: /proc/<pid>/environ shows the
    environment a process image STARTED with, for as long as it runs.
    So they are written, with no other process started, to an anonymous
    in-memory file, and the program re-executes itself without them,
    passing only that file's descriptor. action.yaml has the shell exec
    this process, so no parent keeps them either.

    The file has no name on any filesystem, so there is nothing to
    clean up: whenever the process ends, cancelled or not, the kernel
    frees it. The new image receives SIGNING_ENVIRONMENT and nothing
    else, so no other secret the job carries follows it either.
    """
    values = {name: os.environ.get(name, "") for name in SECRET_INPUTS}
    env = {name: os.environ[name] for name in SIGNING_ENVIRONMENT if name in os.environ}
    env["PATH"] = SYSTEM_PATH
    for name, value in values.items():
        env["HAVE_" + name] = "true" if value.strip() else "false"
    descriptor = write_handoff(values)
    argv = [sys.executable, "-E", "-s", __file__, "sign-handoff", str(descriptor)]
    try:
        os.execve(sys.executable, argv, env)
    except OSError as exc:
        os.close(descriptor)
        raise ActionError(
            f"cannot re-execute without the secret inputs: {exc}"
        ) from None


def write_handoff(values: dict[str, str]) -> int:
    """Return an inheritable descriptor for an anonymous file holding
    the secrets, positioned at its start."""
    descriptor = os.memfd_create("sigul-handoff")
    os.set_inheritable(descriptor, True)
    # NUL-separated: an environment value cannot contain one. Encoded
    # as the environment was decoded, so bytes that are not UTF-8 --
    # which Python carries as surrogates -- survive the trip rather
    # than fail it.
    data = memoryview(b"\0".join(os.fsencode(values[name]) for name in SECRET_INPUTS))
    while data:
        data = data[os.write(descriptor, data) :]
    _ = os.lseek(descriptor, 0, os.SEEK_SET)
    return descriptor


def read_handoff(descriptor: int) -> dict[str, str]:
    """Read the secrets back, and close the descriptor before any child
    process could inherit it."""
    chunks: list[bytes] = []
    try:
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    fields = b"".join(chunks).split(b"\0")
    if len(fields) != len(SECRET_INPUTS):
        raise ActionError("the secret handoff is malformed")
    return {
        name: os.fsdecode(field)
        for name, field in zip(SECRET_INPUTS, fields, strict=True)
    }


def command_sign_handoff(descriptor: int) -> None:
    """The second stage of 'sign', running without the secret inputs."""
    values = read_handoff(descriptor)
    check_runtime()
    plan = build_plan(os.environ, PINS_DIR)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        _ = signal.signal(signum, on_signal)
    sign(plan, values)


def command_pin(name: str) -> None:
    if name not in NICKNAMES:
        raise ActionError(f"no built-in container named '{name}'")
    print(read_pin(PINS_DIR / name / "Dockerfile"))


def main(argv: Sequence[str]) -> int:
    try:
        if len(argv) == 1 and argv[0] == "validate":
            command_validate()
        elif len(argv) == 1 and argv[0] == "sign":
            command_sign()
        elif len(argv) == 2 and argv[0] == "sign-handoff" and argv[1].isdigit():
            command_sign_handoff(int(argv[1]))
        elif len(argv) == 2 and argv[0] == "pin":
            command_pin(argv[1])
        else:
            error("usage: sigul_action.py validate | sign | pin <legacy|modern>")
            return 2
    except ActionError as exc:
        for line in str(exc).splitlines() or ["failed"]:
            error(line)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
