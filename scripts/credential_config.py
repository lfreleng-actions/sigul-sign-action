# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Parse and rewrite Sigul INI values without disclosing configuration data."""

from __future__ import annotations

import configparser
import io
from pathlib import PurePosixPath

from action_common import ActionError

MAX_CONFIG_BYTES = 1024 * 1024


def parse_configuration(text: str) -> configparser.RawConfigParser:
    """Use Sigul's raw INI semantics, including literal percent signs.

    Non-strict parsing retains the legacy client's last-option-wins behavior
    and the action's support for duplicate nss-dir entries. Serialization
    collapses duplicates so the modern client sees an unambiguous file.
    """
    try:
        if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise ActionError("Sigul configuration exceeds 1 MiB")
        parser = configparser.RawConfigParser(delimiters=(":", "="), strict=False)
        parser.read_string(text)
        return parser
    except (configparser.Error, ValueError, UnicodeError):
        raise ActionError("Sigul configuration is not valid INI") from None


def rewrite_nss_dir(text: str, container_nss: str, add_if_missing: bool) -> str:
    """Rewrite an entire parsed option, preserving all other effective values."""
    path = PurePosixPath(container_nss)
    if (
        not path.is_absolute()
        or not container_nss.isprintable()
        or "\\" in container_nss
        or any(part == ".." or part != part.strip() for part in path.parts)
    ):
        raise ActionError("The container NSS directory is not a safe absolute path")
    parser = parse_configuration(text)
    if add_if_missing or parser.has_option("nss", "nss-dir"):
        if not parser.has_section("nss"):
            parser.add_section("nss")
        parser.set("nss", "nss-dir", container_nss)
    try:
        output = io.StringIO()
        parser.write(output)
        rendered = output.getvalue()
        # Fail closed for values that INI serialization cannot round-trip,
        # without printing the value or a ConfigParser exception containing it.
        again = parse_configuration(rendered)
        if dict(parser) != dict(again):
            raise ActionError("Sigul configuration cannot be rewritten safely")
        return rendered
    except (configparser.Error, ValueError):
        raise ActionError("Sigul configuration cannot be rewritten safely") from None
