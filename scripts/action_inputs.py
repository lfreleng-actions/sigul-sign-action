#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Turn the action's inputs into a signing plan, or reject them.

Runs on the RUNNER, under Python 3.10 or later, in both of the
action's steps: the validation step, whose environment holds no
credential, and the signing step, which rebuilds the same plan before
writing anything. A misconfigured call therefore fails before any
secret reaches the disk.

The inputs are lfit/sigul-sign-action's, with their behaviour, so a
caller migrates by changing only its 'uses:' line. The additions --
container selection, dry-run, push-tag, exclusions, retries -- are
optional, and their defaults reproduce that action. The client image
and hosts entries are chosen in client_image.py, and the files to sign
in sign_targets.py.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from action_common import ActionError, InputError, Messages
from client_image import HostEntry, Image, resolve_hosts, resolve_image
from git_tag import check_tag_name, workspace_git_dir
from sign_targets import SignTarget, plan_sign_data

SIGN_TYPES = ("sign-data", "sign-git-tag")
CREDENTIAL_INPUTS = ("sigul-conf", "sigul-pass", "sigul-pki")


@dataclass(frozen=True)
class Plan:
    """Everything the signing step needs, validated."""

    sign_type: str
    dry_run: bool
    push_tag: bool
    key_name: str
    image: Image
    hosts: tuple[HostEntry, ...]
    targets: tuple[SignTarget, ...]
    tag: str
    max_retries: int
    retry_delay: int
    gh_user: str
    workspace: Path
    messages: Messages


def parse_bool(name: str, raw: str) -> bool:
    """Parse a 'true'/'false' input."""
    value = raw.strip().lower()
    if value in ("true", "false"):
        return value == "true"
    raise InputError(f"{name} must be 'true' or 'false' (got '{raw}')")


def parse_int(name: str, raw: str, minimum: int) -> int:
    """Parse a non-negative integer input with a lower bound."""
    value = raw.strip()
    if not value.isdigit():
        raise InputError(f"{name} must be a non-negative integer (got '{raw}')")
    number = int(value)
    if number < minimum:
        raise InputError(f"{name} must be at least {minimum}")
    return number


def require_inputs(env: Mapping[str, str]) -> tuple[str, str, str]:
    """Return sign-type, sign-object and sigul-key-name, checking every
    input the legacy action required. Credentials are seen only as
    HAVE_* flags, so this runs in the validation step too."""
    sign_type = env.get("SIGN_TYPE", "").strip() or "sign-data"
    if sign_type not in SIGN_TYPES:
        raise InputError(
            f"sign-type must be 'sign-data' or 'sign-git-tag', got '{sign_type}'"
        )
    sign_object = env.get("SIGN_OBJECT", "")
    if not sign_object.strip():
        raise InputError("Input 'sign-object' is required")
    key_name = env.get("SIGUL_KEY_NAME", "").strip()
    if not key_name:
        raise InputError("Input 'sigul-key-name' is required")
    for name in CREDENTIAL_INPUTS:
        if env.get("HAVE_" + name.upper().replace("-", "_")) != "true":
            raise InputError(f"Input '{name}' is required")
    return sign_type, sign_object, key_name


def build_plan(
    env: Mapping[str, str],
    pins_dir: Path,
    tag_checker: Callable[[str], None] = check_tag_name,
) -> Plan:
    """Validate every input and return the plan."""
    messages = Messages()
    workspace_raw = env.get("GITHUB_WORKSPACE", "")
    if not workspace_raw or not os.path.isdir(workspace_raw):
        raise ActionError("GITHUB_WORKSPACE is not set to a directory")
    workspace = Path(workspace_raw)
    sign_type, sign_object, key_name = require_inputs(env)

    dry_run = parse_bool("dry-run", env.get("DRY_RUN", "false"))
    push_tag = parse_bool("push-tag", env.get("PUSH_TAG", "true"))
    max_retries = parse_int("max-retries", env.get("MAX_RETRIES", "5"), 1)
    retry_delay = parse_int("retry-delay", env.get("RETRY_DELAY", "15"), 0)

    image = resolve_image(
        env.get("CONTAINER", ""),
        env.get("CONTAINER_IMAGE", ""),
        env.get("CONTAINER_TAG", ""),
        env.get("CONTAINER_DIGEST", ""),
        pins_dir,
    )
    hosts = resolve_hosts(
        env.get("HOSTS_ENTRY", "auto"),
        env.get("SIGUL_IP", ""),
        env.get("SIGUL_URI", ""),
        image.source,
        messages,
    )

    have_gh_key = env.get("HAVE_GH_KEY") == "true"
    targets: tuple[SignTarget, ...] = ()
    tag = ""
    if sign_type == "sign-data":
        excludes = [
            p.strip() for p in env.get("EXCLUDE_GLOBS", "").splitlines() if p.strip()
        ]
        targets = plan_sign_data(sign_object, workspace, excludes, messages)
        if have_gh_key:
            messages.notices.append("gh-key is not used for sign-data")
    else:
        tag = sign_object.strip()
        tag_checker(tag)
        _ = workspace_git_dir(workspace)
        if push_tag and not have_gh_key:
            raise InputError(
                "Input 'gh-key' is required for sign-git-tag, which pushes the "
                + "signed tag; set push-tag: false to sign without pushing"
            )

    gh_user = env.get("GH_USER", "").strip() or env.get("GITHUB_ACTOR", "").strip()
    return Plan(
        sign_type=sign_type,
        dry_run=dry_run,
        push_tag=push_tag,
        key_name=key_name,
        image=image,
        hosts=hosts,
        targets=targets,
        tag=tag,
        max_retries=max_retries,
        retry_delay=retry_delay,
        gh_user=gh_user or "x-access-token",
        workspace=workspace,
        messages=messages,
    )
