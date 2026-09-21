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
set -eu

sigulpath="${SIGULPATH:-/usr/share/sigul}"
fallback=""
for candidate in python3 python; do
    command -v "${candidate}" >/dev/null 2>&1 || continue
    [ -n "${fallback}" ] || fallback="${candidate}"
    if PYTHONPATH="${sigulpath}" "${candidate}" -c 'import client' \
        >/dev/null 2>&1; then
        exec "${candidate}" "$@"
    fi
done

if [ -n "${fallback}" ]; then
    exec "${fallback}" "$@"
fi
echo "ERROR: this image has no Python interpreter (python3 or python)" >&2
exit 127
