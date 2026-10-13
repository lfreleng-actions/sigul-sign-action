#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Sourced by action.yaml with PATH already reset to system directories.
# Judge python3 before it runs, including the file, all traversed parents
# and symlinks, and the final target. Match action_common's policy:
# every node must be root-owned, and group/world write bits are refused.
# Any non-root owner could restore its own write permission. Non-root
# additionally refuses paths it can write via ACLs; root does not use -w.
#
# TCB: the invoking /bin/bash, this script, and the fixed distribution
# /usr/bin/stat and /usr/bin/readlink, including their loader/libraries.
# Built-ins check the helpers and their parents before either executes:
# no symlinks, no non-root job ownership/writability, root ownership when
# running as root. Full ownership/mode checks use trusted stat. This does
# not prove stat's own integrity or protect against root/sudo, races, or
# hostile earlier steps of the same job. The job remains the trust boundary.
# Every external helper executes with an EMPTY environment via exec -c;
# signing inputs are never handed to coreutils. Never run candidate Python
# or a helper from the job's PATH to establish trust.
#
# Sets TRUSTED_PYTHON3 to the validated, resolved absolute path and returns
# 0, or leaves it empty, prints a workflow error, and returns 1.

_sigul_trust_error() {
    local path="${1}" reason="${2}"
    path="${path//%/%25}"
    path="${path//$'\r'/%0D}"
    path="${path//$'\n'/%0A}"
    printf '::error::refusing %s: %s\n' "${path}" "${reason}"
}

_sigul_bootstrap_helpers() {
    local helper node
    for helper in /usr/bin/stat /usr/bin/readlink; do
        node="${helper}"
        while :; do
            if [[ -L "${node}" ]] ||
                { [[ "${node}" == "${helper}" ]] &&
                    [[ ! -f "${node}" || ! -x "${node}" ]]; } ||
                { [[ "${node}" != "${helper}" ]] && [[ ! -d "${node}" ]]; }; then
                _sigul_trust_error "${node}" "cannot bootstrap fixed coreutils through this path"
                return 1
            fi
            if { (( EUID == 0 )) && [[ ! -O "${node}" ]]; } ||
                { (( EUID != 0 )) && [[ -O "${node}" || -w "${node}" ]]; }; then
                _sigul_trust_error "${node}" "fixed coreutils path is owner-changeable or writable"
                return 1
            fi
            [[ "${node}" == / ]] && break
            node="${node%/*}"
            node="${node:-/}"
        done
    done
}

_sigul_trusted_mode() {
    local node="${1}" metadata owner mode
    if ! metadata="$(exec -c /usr/bin/stat -c '%u %f' -- "${node}")"; then
        _sigul_trust_error "${node}" "cannot inspect executable path metadata"
        return 1
    fi
    if [[ ! "${metadata}" =~ ^([0-9]+)\ ([0-9a-fA-F]+)$ ]]; then
        _sigul_trust_error "${node}" "invalid metadata from fixed stat"
        return 1
    fi
    owner=$((10#${BASH_REMATCH[1]}))
    mode=$((16#${BASH_REMATCH[2]}))
    # Linux symlinks report 0777; their parents control replacement.
    # Apply ownership to links, but write bits/ACLs to non-links only.
    if (( owner != 0 )) ||
        (( (mode & 0170000) != 0120000 && (mode & 0022) != 0 )) ||
        { (( EUID != 0 && (mode & 0170000) != 0120000 )) && [[ -w "${node}" ]]; }; then
        _sigul_trust_error "${node}" \
            "unsafe ownership or write permissions, so an earlier step could have planted it"
        return 1
    fi
    printf '%s' "${mode}"
}

_sigul_trusted_path() {
    local path="${1}"
    local pending resolved=/ node component target mode more
    local links=0 components=0
    if [[ "${path}" != /* ]]; then
        _sigul_trust_error "${path}" "an absolute executable path is required"
        return 1
    fi
    if ! mode="$(_sigul_trusted_mode /)"; then
        printf '%s\n' "${mode}"
        return 1
    fi
    pending="${path}"
    while [[ -n "${pending}" ]]; do
        (( components += 1 ))
        if (( components > 256 )); then
            _sigul_trust_error "${path}" "more than 256 path components"
            return 1
        fi
        more=0
        if [[ "${pending}" == */* ]]; then
            component="${pending%%/*}"
            pending="${pending#*/}"
            more=1
        else
            component="${pending}"
            pending=""
        fi
        case "${component}" in
            ''|.) continue ;;
            ..)
                resolved="${resolved%/*}"
                resolved="${resolved:-/}"
                continue
                ;;
        esac
        node="${resolved%/}/${component}"
        if ! mode="$(_sigul_trusted_mode "${node}")"; then
            printf '%s\n' "${mode}"
            return 1
        fi
        if (( (mode & 0170000) == 0120000 )); then
            (( links += 1 ))
            if (( links > 40 )); then
                _sigul_trust_error "${path}" "more than 40 symlink hops"
                return 1
            fi
            # A sentinel preserves trailing newlines in a link target;
            # command substitution must not silently change the filename.
            if ! target="$(
                (exec -c /usr/bin/readlink -n -- "${node}") && printf '.'
            )"; then
                _sigul_trust_error "${node}" "cannot read symlink target"
                return 1
            fi
            target="${target%.}"
            if [[ "${target}" == /* ]]; then
                resolved=/
            fi
            if (( more )); then
                pending="${target}/${pending}"
            else
                pending="${target}"
            fi
            continue
        fi
        if (( more )); then
            if (( (mode & 0170000) != 0040000 )); then
                _sigul_trust_error "${node}" "not a directory"
                return 1
            fi
            resolved="${node}"
        elif (( (mode & 0170000) != 0100000 )) || [[ ! -x "${node}" ]]; then
            _sigul_trust_error "${node}" "not a regular executable"
            return 1
        else
            printf '%s' "${node}"
            return 0
        fi
    done
    _sigul_trust_error "${path}" "not a regular executable"
    return 1
}

# shellcheck disable=SC2034  # set for the sourcing step to run
trusted_python3() {
    local candidate checked helper
    TRUSTED_PYTHON3=""
    _sigul_bootstrap_helpers || return 1
    for helper in /usr/bin/stat /usr/bin/readlink; do
        if ! checked="$(_sigul_trusted_path "${helper}")"; then
            printf '%s\n' "${checked}"
            return 1
        fi
    done
    if ! candidate="$(type -P python3)"; then
        echo "::error::python3 is required on the runner"
        return 1
    fi
    if ! checked="$(_sigul_trusted_path "${candidate}" && printf '.')"; then
        printf '%s\n' "${checked}"
        return 1
    fi
    TRUSTED_PYTHON3="${checked%.}"
}
