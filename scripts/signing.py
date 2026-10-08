#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Sign, once the plan is validated: the 'sign' command's work.

Runs on the RUNNER, under Python 3.10 or later, in a process whose
environment holds no secret (see sigul_action.command_sign). It pulls
the client image, materialises the credentials in a private temporary
directory -- in memory, where the runner has a tmpfs -- runs the Sigul
client in a container, and records the result. The directory is
removed on every exit path, cancellation included: a composite action
has no post step, so cleanup belongs to the step that created the
material.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import tempfile
from pathlib import Path

from action_common import (
    ActionError,
    info,
    markdown_code,
    set_output,
    shred_file,
    summarise,
    warning,
)
from action_inputs import Plan
from client_container import (
    CONTAINER_CREDS,
    CONTAINER_REPO,
    ContainerRun,
    bind,
    container_argv,
    container_user,
    daemon_security_options,
    pull_image,
    remove_container,
    run_container,
    uses_selinux,
)
from git_tag import SigningRepository, workspace_git_dir, write_tag_ref
from gpg_bundle import kill_gpg_agent
from prepare_credentials import prepare

# A dry run does no signing, so it has no business running long; a
# real run's duration scales with the work and is the job's to bound.
DRY_RUN_TIMEOUT_SECONDS = 600

SUMMARY_FILE_LIMIT = 50

# Where the key material is unpacked, when it can be: a tmpfs, so that
# nothing written there reaches a disk. Every Linux the action runs on
# mounts one here, apart from some container runtimes.
SHARED_MEMORY = "/dev/shm"


def is_memory_backed(path: str) -> bool:
    """Return True when path is itself a tmpfs mount, per /proc/mounts.

    Without a readable mount table, which is Linux's, nothing is known
    to be in memory.
    """
    table = Path("/proc/mounts")
    if not table.is_file():
        return False
    for line in table.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == path and fields[2] == "tmpfs":
            return True
    return False


def private_directory(prefix: str, fallback: str | None) -> Path:
    """Create a mode-0700 temporary directory, in memory where possible.

    Key material written to a tmpfs never reaches a disk, which the
    overwrite in destroy() cannot promise on a journalling or
    copy-on-write filesystem; the path is also short, as gpg-agent's
    socket needs. Where /dev/shm is missing, not a tmpfs or not
    writable, the fallback serves and the overwrite is what it always
    was. lfit/sigul-sign-action 2.0.0 made the same choice.
    """
    if is_memory_backed(SHARED_MEMORY) and os.access(SHARED_MEMORY, os.W_OK):
        return Path(tempfile.mkdtemp(prefix=prefix, dir=SHARED_MEMORY))
    return Path(tempfile.mkdtemp(prefix=prefix, dir=fallback))


def clear_stale_signatures(plan: Plan) -> None:
    """Remove every signature this run will write, before signing.

    A failed run then leaves no signature from an earlier one behind
    for any file it was asked to sign.
    """
    removed = 0
    for target in plan.targets:
        if os.path.lexists(target.output):
            os.remove(target.output)
            removed += 1
    if removed:
        info(f"Removed {removed} signature(s) left by an earlier run")


def write_manifest(path: Path, plan: Plan) -> None:
    """Write the NUL-separated (source, output) pairs for the container."""
    data = b"".join(
        os.fsencode(target.source) + b"\0" + os.fsencode(target.output) + b"\0"
        for target in plan.targets
    )
    path.touch(mode=0o600)
    _ = path.write_bytes(data)


def destroy(path: Path) -> None:
    """Overwrite every file in a directory tree, then remove the tree.

    The runner may be reused, so nothing that held a secret is merely
    unlinked. The walk does not follow symlinks, so it overwrites only
    what lies inside the tree. It runs on every exit path, so it must
    not stop part-way: each directory is first made the owner's to
    change, and a file that still cannot be erased is reported, without
    holding up the rest.
    """
    if not path.exists():
        return
    unerased = 0
    _make_owner_writable(path)
    for root, directories, files in os.walk(path):
        for name in directories:
            _make_owner_writable(Path(root) / name)
        for name in files:
            try:
                shred_file(Path(root) / name)
            except OSError:
                unerased += 1
    shutil.rmtree(path, ignore_errors=True)
    if unerased or path.exists():
        warning(
            f"could not erase {unerased} file(s) under {path}"
            + ("; the directory remains" if path.exists() else "")
        )


def _make_owner_writable(directory: Path) -> None:
    """Give a directory's owner full access, so its entries can go."""
    status = directory.lstat()
    if stat.S_ISDIR(status.st_mode) and status.st_mode & stat.S_IRWXU != stat.S_IRWXU:
        os.chmod(directory, stat.S_IMODE(status.st_mode) | stat.S_IRWXU)


def sign_data(run: ContainerRun) -> None:
    """Sign the planned files, or prove they could be signed."""
    plan = run.plan
    write_manifest(run.creds / "manifest", plan)
    workspace = os.path.realpath(plan.workspace)
    environment = {"MANIFEST": f"{CONTAINER_CREDS}/manifest"}
    if plan.dry_run:
        environment["MODE"] = "sign-data"
    else:
        environment["COUNT_FILE"] = f"{CONTAINER_CREDS}/count"
    script = "probe.py" if plan.dry_run else "sign_data.py"
    argv = container_argv(
        run, [bind(workspace, workspace)], environment, workspace, script
    )
    status = run_container(
        argv, run.name, DRY_RUN_TIMEOUT_SECONDS if plan.dry_run else None
    )
    count_file = run.creds / "count"
    signed = count_file.read_text().strip() if count_file.is_file() else "0"
    if status != 0:
        if plan.dry_run:
            raise ActionError(
                "The dry run failed; the container's output above says why"
            )
        raise ActionError(
            f"Signing failed; {signed} of {len(plan.targets)} file(s) signed"
        )
    if plan.dry_run:
        set_output("signed_count", "0")
        lines = [
            f"### Sigul dry run passed: {len(plan.targets)} file(s) would be signed",
            "",
        ]
        lines += [
            f"- {markdown_code(t.name)}" for t in plan.targets[:SUMMARY_FILE_LIMIT]
        ]
        if len(plan.targets) > SUMMARY_FILE_LIMIT:
            lines.append(f"- … and {len(plan.targets) - SUMMARY_FILE_LIMIT} more")
        summarise(lines)
        return
    if signed != str(len(plan.targets)):
        raise ActionError(f"signed {signed} of {len(plan.targets)} file(s)")
    info(f"Signed {signed} file(s)")
    set_output("signed_count", signed)
    summarise([f"Signed {signed} file(s) with Sigul ✅"])


def sign_git_tag(run: ContainerRun, work: Path, gh_key: str) -> None:
    """Sign the tag in a private repository, record it, push it."""
    plan = run.plan
    workspace_git = workspace_git_dir(plan.workspace)
    repo = SigningRepository(
        work / "repo", work / "home", workspace_git, isolated=plan.dry_run
    )
    repo.create()
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    url = f"{server}/{os.environ.get('GITHUB_REPOSITORY', '')}"
    # Unauthenticated, from the repository the tag is pushed to, as
    # the legacy action fetched it. A fetched tag replaces the local one.
    reason = repo.fetch_tag(url, plan.tag)
    unsigned = repo.tag_oid(plan.tag)
    if reason or unsigned is None:
        if reason:
            warning(
                f"Fetching the tag from {url} failed ({reason}); signing the local tag"
            )
        unsigned = repo.adopt_workspace_tag(plan.tag)
    repo.require_annotated(plan.tag, unsigned)

    if plan.dry_run:
        # Its own object store, borrowing the workspace's read-only.
        objects = f"{CONTAINER_REPO}/.git/objects"
        workspace_store = bind(
            repo.workspace_objects, str(repo.workspace_objects), readonly=True
        )
    else:
        objects = str(repo.objects)
        workspace_store = bind(repo.objects, objects)
    environment = {
        "GIT_TAG": plan.tag,
        "GIT_OBJECT_DIRECTORY": objects,
        "GIT_CONFIG_NOSYSTEM": "1",
        # HOME is the unpacked bundle, so that sigul finds its
        # .sigul/client.conf; git would read a .gitconfig there too,
        # which can name commands. Nothing in the bundle is git's to
        # configure. The legacy image's git 1.8 predates this variable,
        # so prepare_credentials refuses a bundle that carries a git
        # configuration at all; this covers the git that honours it.
        "GIT_CONFIG_GLOBAL": os.devnull,
        # Trust the private repository this step created, and nothing
        # else. Where the container sees the mount under another owner
        # -- rootless Docker, user-namespace remapping, Docker Desktop --
        # git 2.35.2 and later otherwise refuse it as 'dubious
        # ownership'. safe.directory is honoured only from this level of
        # configuration, never from a repository's own.
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": CONTAINER_REPO,
    }
    if plan.dry_run:
        environment["MODE"] = "sign-git-tag"
    script = "probe.py" if plan.dry_run else "sign_git_tag.py"
    mounts = [bind(repo.root, CONTAINER_REPO), workspace_store]
    argv = container_argv(run, mounts, environment, CONTAINER_REPO, script)
    status = run_container(
        argv, run.name, DRY_RUN_TIMEOUT_SECONDS if plan.dry_run else None
    )
    if status != 0:
        if plan.dry_run:
            raise ActionError(
                "The dry run failed; the container's output above says why"
            )
        raise ActionError(f"Signing failed for tag: {plan.tag}")
    set_output("signed_count", "0")
    if plan.dry_run:
        summarise(
            [f"### Sigul dry run passed: tag {markdown_code(plan.tag)} would be signed"]
        )
        return

    signed = repo.signed_oid(plan.tag, unsigned)
    # Key material goes before the token is ever written.
    destroy(run.creds)
    write_tag_ref(workspace_git, plan.tag, signed)
    info(f"Signed tag {plan.tag}: {signed}")
    if plan.push_tag:
        repo.push_tag(server, url, plan.tag, plan.gh_user, gh_key)
        info(f"Pushed signed tag {plan.tag} to {url}")
        summarise([f"Signed and pushed tag {markdown_code(plan.tag)} with Sigul ✅"])
    else:
        summarise([f"Signed tag {markdown_code(plan.tag)} with Sigul (not pushed) ✅"])


def sign(plan: Plan, values: dict[str, str]) -> None:
    """Materialise credentials, run the container, record the result."""
    if plan.sign_type == "sign-data" and not plan.dry_run:
        clear_stale_signatures(plan)
    # Both before any credential is written: a daemon the client cannot
    # run under, or an image it cannot pull, fails here.
    security_options = daemon_security_options()
    user = container_user(security_options)
    selinux = uses_selinux(security_options)
    pulled = pull_image(plan.image)
    set_output("container_image", pulled.resolved)

    work = private_directory("sigul.", os.environ.get("RUNNER_TEMP") or None)
    # gpg-agent puts its socket in the gpg home, and a Unix socket path
    # is limited to around 100 characters, which a self-hosted runner's
    # RUNNER_TEMP can already approach. Short of a tmpfs, /tmp keeps
    # the path short, where TMPDIR need not.
    gnupg = private_directory("sigul-gpg.", "/tmp" if os.path.isdir("/tmp") else None)
    info(
        "Credentials unpack in memory"
        if work.parent == Path(SHARED_MEMORY)
        else f"Credentials unpack under {work.parent}; no tmpfs is available"
    )
    name = f"sigul-sign-{secrets.token_hex(6)}"
    creds = work / "creds"
    try:
        prepared = prepare(
            creds,
            gnupg,
            CONTAINER_CREDS,
            values["SIGUL_CONF"],
            values["SIGUL_PASS"],
            values["SIGUL_PKI"],
        )
        kill_gpg_agent(gnupg)
        destroy(gnupg)
        run = ContainerRun(plan, pulled, prepared, creds, name, user, selinux)
        if plan.sign_type == "sign-data":
            sign_data(run)
        else:
            sign_git_tag(run, work, values["GH_KEY"])
    finally:
        # The key material first, and nothing that could wait on the
        # daemon before it: a cancelled step has about ten seconds
        # before the runner kills it, and run_container has already
        # asked for any container still running to be removed. The
        # container holds the same files through its mount, and is
        # gone, or going, by the time they are erased here.
        destroy(work)
        kill_gpg_agent(gnupg)
        destroy(gnupg)
        remove_container(name)
