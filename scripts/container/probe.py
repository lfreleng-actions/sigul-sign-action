#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Dry run: prove a signing run would work, without signing anything.

Runs INSIDE the signing container, under either Python 2.7 or 3.x
(see container_common.py for why), with exactly the mounts, user,
hosts entries and environment a real run gets. It checks, in order:

  1. the sigul client runs;
  2. sigul's own configuration loader accepts the client configuration
     -- the caller's client.conf layered under the bundle's
     .sigul/client.conf, as the legacy action layered them -- and the
     effective bridge matches EXPECTED_BRIDGE, when supplied;
  3. sigul's own NSS initialisation opens the database and accepts its
     password;
  4. the client certificate named in the configuration is present,
     has its private key, and is within its validity period;
  5. the bridge hostname resolves, honouring any hosts entry the action
     added. Deliberately no connection: a Sigul bridge serves clients
     through a serial accept loop and starts a TLS handshake on every
     connection, so a bare probe disturbs it (sigul-docker-k8s keeps
     its own health checks off the listeners for this reason). Only a
     real signing run proves the bridge reachable;
  6. the work itself is reachable: every file to sign is readable and
     its signature's directory present, or the tag resolves in the
     signing repository. The runner checks output permissions before
     mounting the data workspace read-only.

Steps 2 to 4 import sigul's modules rather than reimplementing them,
so the check is what the client would actually do, not an
approximation of it. They are the steps sigul performs before it
opens a connection.

Environment (required unless noted):
  MODE            'sign-data' or 'sign-git-tag'
  MANIFEST        NUL-separated source/output pairs (sign-data)
  GIT_TAG         tag to sign (sign-git-tag)
  SIGULPATH       where sigul's modules live (optional)
  EXPECTED_BRIDGE normalized DNS_HOST:PORT guard (optional, empty disables)
"""

from __future__ import print_function

import os
import socket
import subprocess

from client_configuration import (
    check_expected_bridge,
    load_configuration,
    load_sigul_modules,
)
from container_common import (
    fail,
    git_output,
    info,
    read_manifest,
    require_env,
    set_default_user,
)


def check_client_runs():
    """sigul --version exits zero."""
    if subprocess.call(["sigul", "--version"]) != 0:
        fail("the sigul client does not run in this image")


def report_configuration(config):
    """Describe the loaded configuration only after the endpoint guard passes."""
    info(
        "configuration: bridge {}:{}, server {}, user {}, certificate '{}'".format(
            config.bridge_hostname,
            config.bridge_port,
            config.server_hostname,
            config.user_name,
            config.client_cert_nickname,
        )
    )
    info("NSS database: " + config.nss_dir)


def check_nss(utils, config):
    """Open the NSS database and find the client certificate and key."""
    import nss.nss

    init_error = getattr(utils, "NSSInitError", Exception)
    try:
        utils.nss_init(config)
    except init_error as error:
        fail("NSS: {}".format(error))
    except Exception as error:  # nss.error.NSPRError and friends
        fail("NSS initialisation failed: {}".format(error))

    nickname = config.client_cert_nickname
    try:
        cert = nss.nss.find_cert_from_nickname(nickname)
    except Exception as error:
        fail("client certificate '{}' not found: {}".format(nickname, error))
    try:
        nss.nss.find_key_by_any_cert(cert)
    except Exception as error:
        fail("no private key for certificate '{}': {}".format(nickname, error))

    info("client certificate: " + str(cert.subject))
    not_after = getattr(cert, "valid_not_after_str", "")
    if not_after:
        info("certificate valid until " + not_after)
    check_times = getattr(cert, "check_valid_times", None)
    if check_times is not None:
        # 0 is secCertTimeValid; 1 expired, 2 not yet valid.
        validity = check_times()
        if validity == 1:
            fail("client certificate '{}' has expired".format(nickname))
        if validity == 2:
            fail("client certificate '{}' is not valid yet".format(nickname))


def check_bridge(config):
    """Resolve the bridge hostname without connecting to it."""
    host = config.bridge_hostname
    port = int(config.bridge_port)
    try:
        found = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as error:
        fail("bridge host {} does not resolve: {}".format(host, error))
    addresses = sorted({entry[4][0] for entry in found})
    info(
        "bridge {}:{} resolves to {} (not connected to)".format(
            host, port, ", ".join(addresses)
        )
    )


def check_files(manifest):
    """Read sources without requesting write access to the read-only mount."""
    pairs = read_manifest(manifest)
    for source, output in pairs:
        try:
            open(source, "rb").close()
        except (IOError, OSError) as error:
            fail("cannot read {}: {}".format(source, error))
        directory = os.path.dirname(output)
        if not os.path.isdir(directory):
            fail("signature directory is missing: " + directory)
    info(
        "{} file(s) readable; output permissions checked on the runner".format(
            len(pairs)
        )
    )
    return len(pairs)


def check_tag(tag):
    """The tag resolves to an annotated tag in the signing repository."""
    status, oid = git_output(["rev-parse", "-q", "--verify", "refs/tags/" + tag])
    if status != 0 or not oid:
        fail("tag does not resolve in the signing repository: " + tag)
    status, kind = git_output(["cat-file", "-t", oid])
    if status != 0 or kind != "tag":
        fail("{} is not an annotated tag ({})".format(tag, kind or "unreadable"))
    info("tag {} resolves to annotated tag {}".format(tag, oid))


def main():
    set_default_user()
    mode = require_env("MODE")
    if mode not in ("sign-data", "sign-git-tag"):
        fail("unknown MODE: " + mode)

    check_client_runs()
    client, utils = load_sigul_modules()
    config = load_configuration(client, utils)
    check_expected_bridge(config, os.environ.get("EXPECTED_BRIDGE", ""))
    report_configuration(config)
    check_nss(utils, config)
    check_bridge(config)
    if mode == "sign-data":
        check_files(require_env("MANIFEST"))
    else:
        check_tag(require_env("GIT_TAG"))

    info("dry run: every check passed; nothing was signed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
