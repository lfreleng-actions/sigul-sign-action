#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Smoke-test the container entrypoints under the LEGACY interpreter.
#
# Runs inside the pinned Sigul image, whose CentOS 7 base ships Python
# 2.7 and no python3. Every other test in this repository runs the same
# scripts under Python 3 on the runner, which proves nothing about the
# interpreter the only usable backend actually uses: a Python-3-only
# construct would pass all of those and still break production.
#
# Expects /s to be a read-only mount of the repository's scripts/
# directory. A mock sigul is installed below, so no signing server is
# contacted.

set -eu

echo "interpreter: $(python --version 2>&1)"

work=/tmp/legacy-check
rm -rf "${work}"
mkdir -p "${work}/bin" "${work}/tree/nested"
cp /s/*.py "${work}/"

# Syntax first. A Python-3-only construct fails here, before any
# behaviour is exercised.
cd "${work}"
for script in sign_data.py sign_git_tag.py; do
    python -m py_compile "${script}"
    echo "  ${script}: parses"
done

# A mock sigul: honours -o by writing the named file, and exits zero.
cat > "${work}/bin/sigul" <<'MOCK'
#!/bin/bash
prev=""
for arg in "$@"; do
    if [ "${prev}" = "-o" ]; then
        echo "MOCK SIGNATURE" > "${arg}"
    fi
    prev="${arg}"
done
exit 0
MOCK
chmod +x "${work}/bin/sigul"
export PATH="${work}/bin:${PATH}"

echo a > "${work}/tree/a.jar"
echo c > "${work}/tree/nested/c.jar"
echo x > "${work}/tree/a.jar.asc"
: > "${work}/conf"
printf 'p\0\n' > "${work}/pass"

run_sign() {
    SIGN_TARGET="${work}/tree" \
    SIGUL_CONFIG="${work}/conf" \
    SIGUL_KEY=mock-key \
    SIGUL_PASSWORD="${work}/pass" \
    COUNT_FILE="$1" \
    MAX_RETRIES=2 \
    RETRY_DELAY=0 \
    EXCLUDE_GLOBS='*.asc' \
        python "${work}/sign_data.py"
}

# Two signable files: the .asc is excluded and the nested one found.
run_sign "${work}/count"
signed="$(cat "${work}/count")"
if [ "${signed}" != "2" ]; then
    echo "ERROR: signed ${signed} file(s), expected 2" >&2
    exit 1
fi
if [ ! -f "${work}/tree/nested/c.jar.asc" ]; then
    echo "ERROR: nested file was not signed" >&2
    exit 1
fi
if [ -f "${work}/tree/a.jar.asc.asc" ]; then
    echo "ERROR: excluded file was signed" >&2
    exit 1
fi
echo "  directory mode: 2 signed, exclusions honoured"

# A FIFO must be skipped rather than handed to sigul, which would
# block on it indefinitely. os.walk lists it among filenames, so this
# depends on the explicit regular-file check.
mkfifo "${work}/tree/pipe"
run_sign "${work}/count2"
if [ "$(cat "${work}/count2")" != "2" ]; then
    echo "ERROR: FIFO was not skipped" >&2
    exit 1
fi
echo "  FIFO skipped rather than signed"

# A symlink must be skipped too: following it would sign content from
# outside the tree the caller asked for.
ln -s /etc/hostname "${work}/tree/link.jar"
run_sign "${work}/count3"
if [ "$(cat "${work}/count3")" != "2" ]; then
    echo "ERROR: symlink was not skipped" >&2
    exit 1
fi
echo "  symlink skipped rather than followed"

# Integer validation still rejects rubbish under 2.7.
if MAX_RETRIES=abc \
   SIGN_TARGET="${work}/tree" \
   SIGUL_CONFIG="${work}/conf" \
   SIGUL_KEY=mock-key \
   SIGUL_PASSWORD="${work}/pass" \
   python "${work}/sign_data.py" >/dev/null 2>&1; then
    echo "ERROR: non-integer MAX_RETRIES was accepted" >&2
    exit 1
fi
echo "  non-integer MAX_RETRIES rejected"

# git-tag mode: reject absent and lightweight tags, accept annotated.
repo="${work}/repo"
mkdir -p "${repo}"
cd "${repo}"
git init -q .
git config user.email test@example.com
git config user.name Test
# Force these off: where tag.gpgSign is enabled, 'git tag <name>'
# produces an ANNOTATED tag, and the lightweight case below would
# silently test the wrong thing.
git config tag.gpgSign false
git config commit.gpgsign false
echo content > file
git add file
git commit -qm "initial"
git tag lightweight

kind="$(git cat-file -t refs/tags/lightweight)"
if [ "${kind}" != "commit" ]; then
    echo "ERROR: fixture tag is '${kind}', expected lightweight" >&2
    exit 1
fi

run_tag() {
    GIT_TAG="$1" \
    REPO_DIR="${repo}" \
    SIGUL_CONFIG="${work}/conf" \
    SIGUL_KEY=mock-key \
    SIGUL_PASSWORD="${work}/pass" \
    MAX_RETRIES=2 \
    RETRY_DELAY=0 \
        python "${work}/sign_git_tag.py"
}

for tag in absent lightweight; do
    if run_tag "${tag}" >/dev/null 2>&1; then
        echo "ERROR: accepted tag '${tag}'" >&2
        exit 1
    fi
    echo "  rejected tag: ${tag}"
done

git tag -a annotated -m "annotated"
run_tag annotated >/dev/null
echo "  accepted annotated tag"

echo "Legacy interpreter behaviour matches"
