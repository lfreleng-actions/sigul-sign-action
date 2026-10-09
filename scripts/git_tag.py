#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Git handling for sign-git-tag, on the runner.

No git process ever runs against the workspace repository. Its
configuration is controlled by the calling job, and git can be made to
run commands from it -- an ext:: remote, a filter driver, a hook --
which would then run alongside the signing credentials.
lfit/sigul-sign-action v2.0.0 closed that hole, and this keeps it
closed:

  * the tag is fetched, without credentials, from the repository it is
    pushed to, into a PRIVATE repository with clean configuration whose
    objects live in the workspace's object store (GIT_OBJECT_DIRECTORY);
  * sigul signs there, inside the container;
  * the signed tag is recorded in the workspace by writing a ref file,
    which runs no git at all;
  * the push runs from the private repository, in a clean environment,
    with the token supplied by a credential helper scoped to the
    server, read from a private file. The token is in no process's
    arguments or environment, and in no configuration file.

The workspace's refs are read as files for the same reason.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from action_common import ActionError, shred_file
from git_config import git_env as git_env
from git_config import read_extension as read_extension
from git_config import uses_reftable as uses_reftable
from git_config import uses_sha256 as uses_sha256
from process_control import capture_bytes, capture_text

if TYPE_CHECKING:
    # The standalone container script uses this module name. Keep type analysis
    # on the same name so it does not load the shared source file twice.
    from tag_integrity import BEGIN_SIGNATURE, signature_error
else:
    from container.tag_integrity import BEGIN_SIGNATURE, signature_error

# Retained for callers that display the marker or construct test fixtures.
PGP_SIGNATURE_MARKER = BEGIN_SIGNATURE.decode("ascii")

_OID = re.compile(r"^[0-9a-f]{40}$")


def run_git(
    args: list[str], cwd: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run git, capturing its output."""
    try:
        return capture_text(["git", *args], cwd=cwd, env=env)
    except FileNotFoundError:
        raise ActionError("git is not installed on the runner") from None


def last_line(text: str) -> str:
    """Return the last non-blank line of git's stderr, for a message."""
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def check_tag_name(tag: str) -> None:
    """Accept only a single, well-formed tag name.

    The name becomes part of a force-push refspec, so anything git would
    not accept as refs/tags/<name> could otherwise name another ref.
    Checked from an empty directory with no configuration.
    """
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in tag):
        raise ActionError(f"sign-object is not a valid tag name: '{tag}'")
    with tempfile.TemporaryDirectory() as scratch:
        done = run_git(
            ["check-ref-format", f"refs/tags/{tag}"],
            Path(scratch),
            git_env(Path(scratch)),
        )
    if done.returncode != 0:
        raise ActionError(f"sign-object is not a valid tag name: '{tag}'")


def workspace_git_dir(workspace: Path) -> Path:
    """Return the workspace's .git directory.

    Only a standard checkout is supported. In a linked worktree or a
    submodule, .git is a FILE pointing at metadata elsewhere on the host;
    a symlinked .git likewise points outside the work tree. Neither
    object store would be reachable from inside the container. The same
    goes for an object store that borrows from another through
    objects/info/alternates; a repository that keeps its refs in
    reftables rather than files cannot have its tag recorded by writing
    one; and the client images' git cannot read SHA-256 object names.
    actions/checkout produces none of these. Every refusal happens here,
    in the validation step, before any credential exists.
    """
    dot_git = workspace / ".git"
    if dot_git.is_symlink():
        raise ActionError(
            "the workspace's .git is a symlink; its object store lies outside "
            + "the workspace. Use a standard checkout"
        )
    if not dot_git.is_dir():
        raise ActionError(
            "the workspace has no .git directory; a linked worktree or "
            + "submodule checkout is not supported"
        )
    # The object store is mounted into the signing container, read-write
    # for a real run. A symlinked one would carry that mount to wherever
    # it points, outside the workspace.
    objects = dot_git / "objects"
    if objects.is_symlink() or not objects.is_dir():
        raise ActionError(
            "the workspace's .git/objects is not a directory inside .git; "
            + "its object store lies elsewhere. Use a standard checkout"
        )
    if (objects / "info" / "alternates").exists():
        raise ActionError(
            "the workspace's object store borrows objects from another "
            + "(.git/objects/info/alternates), which the signing container "
            + "could not reach. Use a standard checkout"
        )
    if uses_reftable(dot_git):
        raise ActionError(
            "the workspace keeps its refs in reftables (extensions.refStorage), "
            + "where the signed tag cannot be recorded by writing a ref file. "
            + "Use a checkout with the default ref storage"
        )
    if uses_sha256(dot_git):
        # The legacy client image's git (1.8) predates SHA-256 object
        # names entirely.
        raise ActionError(
            "the workspace names objects with SHA-256 (extensions.objectFormat), "
            + "which the Sigul client images' git does not support"
        )
    return dot_git


def read_ref(git_dir: Path, ref: str) -> str | None:
    """Return the object ID of ref, from a loose ref or packed-refs."""
    loose = git_dir / ref
    if loose.is_file():
        value = loose.read_text(errors="replace").strip()
        return value if _OID.match(value) else None
    packed = git_dir / "packed-refs"
    if not packed.is_file():
        return None
    for line in packed.read_text(errors="replace").splitlines():
        if not line or line[0] in "#^":
            continue
        oid, _, name = line.partition(" ")
        if name == ref and _OID.match(oid):
            return oid
    return None


def read_head(git_dir: Path) -> str | None:
    """Return the object ID HEAD resolves to, or None."""
    head = git_dir / "HEAD"
    if not head.is_file():
        return None
    value = head.read_text(errors="replace").strip()
    if value.startswith("ref: "):
        return read_ref(git_dir, value[len("ref: ") :])
    return value if _OID.match(value) else None


def write_tag_ref(git_dir: Path, tag: str, oid: str) -> None:
    """Point refs/tags/<tag> at oid by writing a loose ref file.

    A loose ref takes precedence over packed-refs. Refuses to follow a
    symlink anywhere below refs/, which could redirect the write
    outside the repository.
    """
    if not _OID.match(oid):
        raise ActionError(f"refusing to record an invalid object ID: {oid}")
    path = git_dir / "refs"
    for part in ["tags", *tag.split("/")[:-1]]:
        if path.is_symlink():
            raise ActionError(f"refusing to write through a symlink: {path}")
        path = path / part
    if path.is_symlink():
        raise ActionError(f"refusing to write through a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True)
    target = path / tag.split("/")[-1]
    handle, temporary = tempfile.mkstemp(prefix=".sigul-ref.", dir=path)
    try:
        with os.fdopen(handle, "w") as stream:
            _ = stream.write(oid + "\n")
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


class SigningRepository:
    """A private repository whose objects live in the workspace.

    'isolated', for a dry run, gives it an object store of its own that
    borrows the workspace's as a read-only alternate, so even a fetch
    adds nothing to the workspace. A real run writes the signed tag
    object, and what the fetch brings, into the workspace's store, where
    the recorded ref needs them.
    """

    def __init__(
        self, root: Path, home: Path, workspace_git: Path, isolated: bool = False
    ) -> None:
        self.root: Path = root
        self.home: Path = home
        self.workspace_git: Path = workspace_git
        self.workspace_objects: Path = (workspace_git / "objects").resolve()
        self.isolated: bool = isolated
        self.objects: Path = (
            root / ".git" / "objects" if isolated else self.workspace_objects
        )
        self._observed_tags: dict[tuple[str, str], str] = {}

    def _git(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return run_git(args, self.root, git_env(self.home, self.objects))

    def create(self) -> None:
        """Initialise the repository and seed a negotiation tip."""
        self.home.mkdir(parents=True, exist_ok=True)
        done = run_git(["init", "-q", str(self.root)], self.home, git_env(self.home))
        if done.returncode != 0:
            raise ActionError(f"git init failed: {last_line(done.stderr)}")
        # This repository cannot judge reachability in the shared object store.
        # Persist these settings so the container's Git obeys them as well.
        for key, value in (("gc.auto", "0"), ("maintenance.auto", "false")):
            done = self._git(["config", "--local", key, value])
            if done.returncode != 0:
                raise ActionError(
                    f"cannot disable Git maintenance: {last_line(done.stderr)}"
                )
        shallow = self.workspace_git / "shallow"
        if shallow.is_file():
            _ = shutil.copyfile(shallow, self.root / ".git" / "shallow")
        if self.isolated:
            alternates = self.objects / "info" / "alternates"
            alternates.parent.mkdir(parents=True, exist_ok=True)
            _ = alternates.write_text(f"{self.workspace_objects}\n")
        # Name the workspace's own HEAD here, so a fetch advertises it as
        # a commit already held and transfers only what is missing,
        # rather than the tag's whole history.
        head = read_head(self.workspace_git)
        if head and self._git(["cat-file", "-e", f"{head}^{{commit}}"]).returncode == 0:
            _ = self._git(["update-ref", "refs/sigul/workspace-head", head])

    def fetch_tag(self, url: str, tag: str) -> str:
        """Fetch the tag without credentials; return '' or the reason it
        could not be fetched."""
        observation = (url, tag)
        _ = self._observed_tags.pop(observation, None)
        done = self._git(
            ["fetch", "-q", "--no-tags", url, f"+refs/tags/{tag}:refs/tags/{tag}"]
        )
        if done.returncode != 0:
            return last_line(done.stderr) or "failed"
        oid = self.tag_oid(tag)
        if oid is None:
            return "the fetched tag has no readable object ID"
        self._observed_tags[observation] = oid
        return ""

    def tag_oid(self, tag: str) -> str | None:
        """Return the object the tag points at here, or None."""
        done = self._git(["rev-parse", "-q", "--verify", f"refs/tags/{tag}"])
        value = done.stdout.strip()
        return value if done.returncode == 0 and _OID.match(value) else None

    def adopt_workspace_tag(self, tag: str) -> str:
        """Use the workspace's own copy of the tag."""
        oid = read_ref(self.workspace_git, f"refs/tags/{tag}")
        if oid is None:
            raise ActionError(f"Tag does not exist: {tag}")
        done = self._git(["update-ref", f"refs/tags/{tag}", oid])
        if done.returncode != 0:
            raise ActionError(
                f"cannot use the workspace's tag {tag}: {last_line(done.stderr)}"
            )
        return oid

    def object_type(self, oid: str) -> str:
        """Return git's type name for an object, or '' if unreadable."""
        done = self._git(["cat-file", "-t", oid])
        return done.stdout.strip() if done.returncode == 0 else ""

    def tag_bytes(self, oid: str) -> bytes:
        """Read a tag without decoding, stripping, or normalizing its payload."""
        try:
            done = capture_bytes(
                ["git", "cat-file", "tag", oid],
                cwd=self.root,
                env=git_env(self.home, self.objects),
            )
        except FileNotFoundError:
            raise ActionError("git is not installed on the runner") from None
        if done.returncode != 0:
            raise ActionError(f"cannot read tag object: {oid}")
        return done.stdout

    def require_annotated(self, tag: str, oid: str) -> None:
        """Fail unless oid is an annotated tag safe to append a signature to."""
        kind = self.object_type(oid)
        if kind != "tag":
            raise ActionError(
                f"{tag} is not an annotated tag ({kind or 'unreadable'}); "
                + "only an annotated tag can carry a signature"
            )
        if not self.tag_bytes(oid).endswith(b"\n"):
            raise ActionError(
                f"the original tag must end with a newline before signing: {tag}"
            )

    def signed_oid(self, tag: str, unsigned: str) -> str:
        """Return the new OID only for the exact original plus one armor block."""
        current = self.tag_oid(tag)
        if current is None or current == unsigned:
            raise ActionError(f"the tag was not signed: {tag}")
        problem = signature_error(self.tag_bytes(unsigned), self.tag_bytes(current))
        if problem:
            raise ActionError(f"{problem}: {tag}")
        return current

    def push_tag(self, server: str, url: str, tag: str, user: str, token: str) -> None:
        """Replace only the remote tag observed by a successful anonymous fetch."""
        observed = self._observed_tags.get((url, tag))
        if observed is None:
            raise ActionError(
                f"cannot push tag {tag} without a successful fetch from the same remote"
            )
        credential = self.home / "git-credential"
        if "'" in str(credential):
            raise ActionError("the temporary directory path contains a quote")
        descriptor = os.open(credential, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            _ = stream.write(f"username={user}\npassword={token}\n")
        # Builtins only: git runs the helper through sh, with the system
        # PATH, where /usr/local/bin comes first and is world-writable on
        # GitHub-hosted runners; a 'cat' planted there would be handed
        # the token. read and printf are builtins of every sh.
        helper = (
            '!f() { test "$1" = get || exit 0; '
            + f"while IFS= read -r line; do printf '%s\\n' \"$line\"; done < '{credential}'; "
            + "}; f"
        )
        try:
            done = self._git(
                [
                    "-c",
                    f"credential.{server}.helper={helper}",
                    "push",
                    "--no-verify",
                    f"--force-with-lease=refs/tags/{tag}:{observed}",
                    url,
                    f"refs/tags/{tag}:refs/tags/{tag}",
                ]
            )
        finally:
            shred_file(credential)
        if done.returncode != 0:
            raise ActionError(
                f"could not push signed tag {tag}: {last_line(done.stderr)}"
            )
