# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Byte-preservation and armor checks shared by the runner and Python 2.7 client.

This checks the appended signature's framing, not its OpenPGP authenticity.
The original may already contain a signature; none of its bytes are stripped.
"""

import re

BEGIN_SIGNATURE = b"-----BEGIN PGP SIGNATURE-----"
END_SIGNATURE = b"-----END PGP SIGNATURE-----"

_ARMOR = re.compile(
    b"\\A-----BEGIN PGP SIGNATURE-----\\r?\\n"
    b"(?:[A-Za-z0-9-]+:[^\\r\\n]*\\r?\\n)*"
    b"\\r?\\n(?P<payload>.+?)\\r?\\n"
    b"-----END PGP SIGNATURE-----(?:\\r?\\n)?\\Z",
    re.DOTALL,
)


def signature_error(original, signed):
    # type: (bytes, bytes) -> str
    """Return '' for an unchanged tag plus one complete, nonempty armor block."""
    if not original.endswith(b"\n"):
        return "the original tag must end with a newline before signing"
    if not signed.startswith(original):
        return "the signed tag changed the original payload"
    armor = _ARMOR.match(signed[len(original) :])
    if armor is None:
        return "the tag carries no complete appended PGP signature"
    payload = armor.group("payload")
    if not payload.strip() or BEGIN_SIGNATURE in payload or END_SIGNATURE in payload:
        return "the appended PGP signature is empty or malformed"
    return ""
