#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Run a container-side script with the image's own Python.
#
# The legacy client image (CentOS 7) ships Python 2.7 as 'python' and
# no python3; the modern one (Fedora) ships python3 and no bare
# 'python'. A bespoke image may carry either, or both. Prefer the
# interpreter that can import Sigul's own client modules, because the
# dry-run probe loads them in-process; any Python serves otherwise,
# since the signing scripts run sigul as a command.
#
# The probe imports from / rather than from the working directory:
# 'python -c' searches the current directory first, and for sign-data
# that is the workspace, whose client.py or utils.py would otherwise
# be imported, and so run, here with the credentials mounted. The
# path to Sigul's modules travels as an argument and goes onto the
# search path inside the probe, and the interpreter runs with no
# other flag, exactly as it will run the script: -E would ignore a
# PYTHONPATH an image relies on, and -s drops /usr/local's
# site-packages on Fedora, where the modern image keeps python-nss,
# so either would fail the probe for an interpreter that is fine.
# The scripts themselves are safe either way: run as files, Python
# searches their own directory first, and probe.py adds SIGULPATH to
# the search itself.
set -eu

sigulpath="${SIGULPATH:-/usr/share/sigul}"
fallback=""
for candidate in python3 python; do
    command -v "${candidate}" >/dev/null 2>&1 || continue
    [ -n "${fallback}" ] || fallback="${candidate}"
    if (cd / && "${candidate}" -c \
        'import sys; sys.path.insert(0, sys.argv[1]); import client' \
        "${sigulpath}") >/dev/null 2>&1; then
        exec "${candidate}" "$@"
    fi
done

if [ -n "${fallback}" ]; then
    exec "${fallback}" "$@"
fi
echo "ERROR: this image has no Python interpreter (python3 or python)" >&2
exit 127
