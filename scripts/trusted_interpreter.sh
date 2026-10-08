#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Find the python3 the action may run, and refuse any other.
#
# Sourced by both steps of action.yaml before anything else runs,
# with PATH already reset to the system's directories. The interpreter
# is the first process a step starts, and the signing step holds the
# secret inputs in its environment by then, so it has to be judged
# before it runs, by the shell alone: one found in a directory an
# earlier step of the job could write to is refused, since GitHub-hosted
# Ubuntu runners leave /usr/local/bin world-writable (see
# action_common.SYSTEM_PATH).
#
#   * Not root: a directory this user can write to is refused, and this
#     user is the one every step of the job runs as.
#   * Root: every directory tests writable, so the mode bits are read
#     instead, with the distribution's own stat by absolute path, as
#     /bin/bash itself is run; a world-writable directory is refused.
#     On a root runner every step is root too and could replace any
#     file, so this is a check against accident, not against intent.
#
# Sets TRUSTED_PYTHON3 and returns 0, or prints a workflow error and
# returns 1. sigul_action.check_runtime repeats the check on the
# interpreter's resolved target and applies it to the other tools.

# shellcheck disable=SC2034  # set for the sourcing step to run
trusted_python3() {
    local candidate directory mode
    if ! candidate="$(type -P python3)"; then
        echo "::error::python3 is required on the runner"
        return 1
    fi
    directory="${candidate%/*}"
    if (( EUID != 0 )); then
        if [[ -w "${directory}" ]]; then
            echo "::error::refusing ${candidate}: ${directory} is writable by" \
                "this user, so an earlier step could have planted it"
            return 1
        fi
    else
        if ! mode="$(/usr/bin/stat -L -c '%a' "${directory}")"; then
            echo "::error::cannot read the permissions of ${directory}"
            return 1
        fi
        if (( 8#${mode} & 2 )); then
            echo "::error::refusing ${candidate}: ${directory} is" \
                "world-writable, so an earlier step could have planted it"
            return 1
        fi
    fi
    TRUSTED_PYTHON3="${candidate}"
}
