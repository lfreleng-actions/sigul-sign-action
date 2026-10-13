# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Load Sigul's effective configuration and enforce an optional bridge guard.

Runs inside the client image under Python 2.7 or 3.x. Sigul itself layers
its system configuration beneath HOME/.sigul/client.conf; do not parse
those files separately here. Loading never reports configuration values,
so a caller can enforce the expectation before logging or using them.
"""

from __future__ import print_function

import getpass
import importlib
import os
import sys

from container_common import fail

SIGUL_USER_CONFIG = "~/.sigul/client.conf"


class PromptRefused(Exception):
    """Raised in place of an interactive NSS password prompt."""


def refuse_prompt(prompt=""):
    """Do not let an NSS prompt consume the signing passphrase from stdin."""
    raise PromptRefused(prompt)


def load_sigul_modules():
    """Import the client and utilities installed in the selected image."""
    sigulpath = os.environ.get("SIGULPATH", "/usr/share/sigul")
    sys.path.insert(0, sigulpath)
    try:
        client = importlib.import_module("client")
        utils = importlib.import_module("utils")
    except Exception:
        fail("cannot load sigul's client modules; check SIGULPATH for this image")
    return client, utils


def load_configuration(client, utils):
    """Use Sigul's loader without leaving the process's prompt handler changed."""
    config_error = getattr(utils, "ConfigurationError", Exception)
    original_prompt = getpass.getpass
    getpass.getpass = refuse_prompt
    try:
        return client.ClientConfiguration(SIGUL_USER_CONFIG)
    except PromptRefused:
        fail(
            "no nss-password is set, in sigul-conf or in the bundle's "
            ".sigul/client.conf; sigul would prompt for it, which a batch "
            "run cannot answer"
        )
    except config_error:
        fail("sigul rejected the client configuration; check its sections and options")
    except Exception:
        fail("could not load the sigul client configuration")
    finally:
        getpass.getpass = original_prompt


def check_expected_bridge(config, expected):
    """Compare the effective endpoint with the runner's normalized expectation."""
    if not expected:
        return
    try:
        host = config.bridge_hostname.lower()
        if host.endswith("."):
            host = host[:-1]
        port = int(config.bridge_port)
        matches = (
            bool(host) and 1 <= port <= 65535 and "{}:{}".format(host, port) == expected
        )
    except (AttributeError, TypeError, ValueError, OverflowError):
        matches = False
    if not matches:
        fail("effective sigul bridge does not match expected-bridge")


def enforce_expected_bridge(expected):
    """Load and check the endpoint only for a caller that opted into the guard."""
    if expected:
        client, utils = load_sigul_modules()
        config = load_configuration(client, utils)
        check_expected_bridge(config, expected)
