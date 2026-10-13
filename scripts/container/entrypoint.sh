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

# Every descendant, including Sigul's own subprocesses, inherits this PATH.
# Retain image-specific absolute locations, but never resolve tools in cwd.
remaining="${PATH:-}"
while :; do
    component="${remaining%%:*}"
    case "${component}" in
        /*) ;;
        *) echo "ERROR: image PATH must contain only nonempty absolute directories" >&2
           exit 1 ;;
    esac
    case "${remaining}" in
        *:*) remaining="${remaining#*:}" ;;
        *) break ;;
    esac
done
export PATH

sigulpath="${SIGULPATH:-/usr/share/sigul}"
case "${sigulpath}" in
    /*) ;;
    *) echo "ERROR: SIGULPATH must be absolute" >&2; exit 1 ;;
esac
fallback=""
for candidate in python3 python; do
    resolved="$(cd / && command -v "${candidate}")" || continue
    case "${resolved}" in
        /*) ;;
        *) echo "ERROR: interpreter path is not absolute" >&2; exit 1 ;;
    esac
    [ -n "${fallback}" ] || fallback="${resolved}"
    if (cd / && "${resolved}" -c \
        'import sys; sys.path.insert(0, sys.argv[1]); import client' \
        "${sigulpath}") >/dev/null 2>&1; then
        exec "${resolved}" "$@"
    fi
done

if [ -n "${fallback}" ]; then
    exec "${fallback}" "$@"
fi
echo "ERROR: this image has no Python interpreter (python3 or python)" >&2
exit 127
