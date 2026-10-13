# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Unit tests for the runner-side scripts.

Run from the repository root with:

    python3 -m unittest discover -s tests -t .

The scripts import one another from scripts/, as Python arranges when
action.yaml runs scripts/sigul_action.py; this puts that directory on
the path for the tests too. They use only the standard library, so
there is nothing to install.
"""

import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
