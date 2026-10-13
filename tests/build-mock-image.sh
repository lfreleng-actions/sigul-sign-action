#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Build a test-only Sigul client image and push it to a local registry.
#
# The image is a real client image -- one the action pins -- with
# tests/mock-sigul placed ahead of the real client on PATH, and the
# passphrase the test credentials use baked in, so the mock can check
# it receives exactly that. Every sign-git-tag also fails its first
# attempt, so each tag test exercises the retry path. The action then
# runs its real signing path against it, named as a bespoke image by
# tag and digest, and nothing reaches a Sigul server.
#
# Usage: build-mock-image.sh BASE_IMAGE PLATFORM REGISTRY NAME
# Prints the pushed reference, name:tag@digest, on stdout.

set -euo pipefail

base="$1"
platform="$2"
registry="$3"
name="$4"
here="$(cd "$(dirname "$0")" && pwd)"
tag="mock"
reference="${registry}/${name}:${tag}"

docker build --quiet --platform "${platform}" --tag "${reference}" \
    --build-arg "BASE=${base}" --file - "${here}" >&2 <<'DOCKERFILE'
ARG BASE
FROM ${BASE}
ENV MOCK_PASSPHRASE=sigul-test-passphrase MOCK_FAIL_TAG_ONCE=1
COPY mock-sigul /usr/local/bin/sigul
DOCKERFILE

docker push --quiet "${reference}" >&2
digest="$(docker image inspect --format '{{join .RepoDigests "\n"}}' "${reference}" |
    grep -F "${registry}/${name}@" | head -n 1 | cut -d@ -f2)"
[ -n "${digest}" ] || { echo "no digest for ${reference}" >&2; exit 1; }
printf '%s@%s\n' "${reference}" "${digest}"
