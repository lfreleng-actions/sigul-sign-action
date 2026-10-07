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
# be imported, and so run, here with the credentials mounted. -E and
# -s keep the job's PYTHON* variables and the user site directory out
# of the search too, as the runner side does for its own interpreter.
# The scripts themselves are safe either way: run as files, Python
# searches their own directory first, and probe.py adds SIGULPATH to
# the search itself.
set -eu

sigulpath="${SIGULPATH:-/usr/share/sigul}"
fallback=""
for candidate in python3 python; do
    command -v "${candidate}" >/dev/null 2>&1 || continue
    [ -n "${fallback}" ] || fallback="${candidate}"
    if (cd / && PYTHONPATH="${sigulpath}" "${candidate}" -E -s -c 'import client') \
        >/dev/null 2>&1; then
        exec "${candidate}" "$@"
    fi
done

if [ -n "${fallback}" ]; then
    exec "${fallback}" "$@"
fi
echo "ERROR: this image has no Python interpreter (python3 or python)" >&2
exit 127
