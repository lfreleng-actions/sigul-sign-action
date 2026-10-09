#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Choose the Sigul client image, and the hosts entries it runs with.

Runs on the RUNNER, under Python 3.10 or later.

The Linux Foundation runs two generations of Sigul whose protocols
differ, so the client image follows the infrastructure and is chosen
explicitly: by nickname, from the pins in containers/*/Dockerfile, or
named exactly as a bespoke image -- never both.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

from action_common import ActionError, InputError, Messages

NICKNAMES = ("legacy", "modern")
HOSTS_ENTRY_MODES = ("auto", "true", "false")

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_DOMAIN = rf"{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*(?::[0-9]+)?"
_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
# Docker's reference grammar. Every component starts with a letter or
# digit, so an image name can never be read as a command-line option.
_NAME = re.compile(rf"^(?:{_DOMAIN}/)?{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    + r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)


@dataclass(frozen=True)
class Image:
    """The Sigul client image to sign with."""

    reference: str
    source: str  # 'legacy', 'modern' or 'bespoke'
    has_digest: bool


@dataclass(frozen=True)
class HostEntry:
    """A hosts entry for the container."""

    name: str
    address: str


def parse_expected_bridge(raw: str) -> str:
    """Validate an optional DNS_HOST:PORT guard without changing hosts entries."""
    value = raw.strip()
    if not value:
        return ""
    message = "expected-bridge must be DNS_HOST:PORT with a port from 1 to 65535"
    host, separator, port = value.partition(":")
    if (
        not separator
        or not _HOSTNAME.fullmatch(host)
        or not re.fullmatch(r"[0-9]+", port)
    ):
        raise InputError(message)
    # Bound conversion even for a very long integer, while accepting leading zeros.
    port = port.lstrip("0") or "0"
    if len(port) > 5 or not 1 <= int(port) <= 65535:
        raise InputError(message)
    return f"{host.removesuffix('.').lower()}:{int(port)}"


def split_reference(raw: str) -> tuple[str, str, str]:
    """Split an image reference into (name, tag, digest), as Docker does:
    a ':' after the last '/' starts the tag."""
    name, _, digest = raw.partition("@")
    tag = ""
    colon = name.rfind(":")
    if colon > name.rfind("/"):
        name, tag = name[:colon], name[colon + 1 :]
    return name, tag, digest


def read_pin(path: Path) -> str:
    """Return the image reference on a pin file's FROM line."""
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise ActionError(f"cannot read the image pin {path}: {exc}") from None
    for line in lines:
        words = line.split()
        if not words or words[0].startswith("#"):
            continue
        if words[0].upper() != "FROM":
            break
        refs = [word for word in words[1:] if not word.startswith("--")]
        if refs:
            name, tag, digest = split_reference(refs[0])
            if _NAME.match(name) and _TAG.match(tag) and _DIGEST.match(digest):
                return refs[0]
        break
    raise ActionError(f"{path} must start with 'FROM <image>:<tag>@sha256:<digest>'")


def bespoke_image(image: str, tag: str, digest: str) -> Image:
    """Validate an image named exactly, by tag, digest or both."""
    if not image:
        raise InputError(
            "'container-tag' and 'container-digest' need 'container-image'"
        )
    name, own_tag, own_digest = split_reference(image)
    if own_tag and tag:
        raise InputError("the tag is given twice: in container-image and container-tag")
    if own_digest and digest:
        raise InputError(
            "the digest is given twice: in container-image and container-digest"
        )
    tag, digest = own_tag or tag, own_digest or digest
    if not _NAME.match(name):
        raise InputError(f"container-image is not a valid image name: '{name}'")
    if tag and not _TAG.match(tag):
        raise InputError(f"container-tag is not a valid tag: '{tag}'")
    if digest and not _DIGEST.match(digest):
        raise InputError(
            f"container-digest must be 'sha256:' and 64 hex digits (got '{digest}')"
        )
    if not tag and not digest:
        raise InputError(
            "a bespoke image needs a tag, a digest or both; refusing to assume 'latest'"
        )
    reference = name + (f":{tag}" if tag else "") + (f"@{digest}" if digest else "")
    return Image(reference=reference, source="bespoke", has_digest=bool(digest))


def resolve_image(
    container: str, image: str, tag: str, digest: str, pins_dir: Path
) -> Image:
    """Choose the client image.

    Either a built-in image by nickname ('container'), or a bespoke one
    named exactly ('container-image', with 'container-tag' and/or
    'container-digest'), never both. Neither selects 'legacy'.
    """
    nickname = container.strip().lower()
    image, tag, digest = image.strip(), tag.strip(), digest.strip()
    if nickname and (image or tag or digest):
        raise InputError(
            "'container' selects a built-in image, while 'container-image', "
            + "'container-tag' and 'container-digest' name a bespoke one. "
            + "Use one or the other, not both"
        )
    if image or tag or digest:
        return bespoke_image(image, tag, digest)
    if nickname and nickname not in NICKNAMES:
        raise InputError(
            f"container must be 'legacy' or 'modern' (got '{container}'); to name "
            + "an image exactly, use container-image instead"
        )
    source = nickname or "legacy"
    return Image(
        reference=read_pin(pins_dir / source / "Dockerfile"),
        source=source,
        has_digest=True,
    )


def _hosts_problems(address: str, names: str) -> list[str]:
    """Return what stops sigul-ip and sigul-uri making a hosts entry."""
    if not address or not names:
        return ["it needs both sigul-ip and sigul-uri"]
    problems: list[str] = []
    try:
        _ = ipaddress.ip_address(address)
    except ValueError:
        problems.append(f"sigul-ip is not an IP address: '{address}'")
    problems.extend(
        f"sigul-uri is not a hostname: '{name}'"
        for name in names.split()
        if not _HOSTNAME.match(name)
    )
    return problems


def resolve_hosts(
    mode: str, address: str, names: str, source: str, messages: Messages
) -> tuple[HostEntry, ...]:
    """Decide the hosts entries for the container.

    The legacy action wrote 'sigul-ip sigul-uri' to /etc/hosts. That
    still happens for the legacy container by default ('auto'), so
    existing callers behave as before; any other container gets it
    only when asked ('true'). Under 'auto', unusable values are skipped
    with a warning, because the legacy action wrote them as a broken
    hosts line and resolved the bridge through DNS regardless.
    """
    mode = mode.strip().lower()
    if mode not in HOSTS_ENTRY_MODES:
        raise InputError(
            f"sigul-hosts-entry must be 'auto', 'true' or 'false' (got '{mode}')"
        )
    address, names = address.strip(), names.strip()
    supplied = bool(address or names)
    if mode == "false" or (mode == "auto" and source != "legacy"):
        if supplied:
            reason = (
                "sigul-hosts-entry is 'false'"
                if mode == "false"
                else "the hosts entry is automatic only for the legacy container, "
                + f"and this is '{source}'; set sigul-hosts-entry: true to add it"
            )
            messages.notices.append(f"sigul-ip and sigul-uri are ignored: {reason}")
        return ()
    if not supplied and mode == "auto":
        return ()
    problems = _hosts_problems(address, names)
    if problems:
        detail = "; ".join(problems)
        if mode == "true":
            raise InputError(f"sigul-hosts-entry is 'true' but {detail}")
        messages.warnings.append(f"no hosts entry was added: {detail}")
        return ()
    # In canonical form, as getaddrinfo() reports addresses, so that the
    # comparison with DNS is of addresses rather than of spellings:
    # '2001:0db8::1' is '2001:db8::1'.
    address = str(ipaddress.ip_address(address))
    return tuple(HostEntry(name=name, address=address) for name in names.split())
