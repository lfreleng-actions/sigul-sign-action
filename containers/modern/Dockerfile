# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Pin for the 'modern' Sigul client: sigul 1.4 on Fedora, built by
# lfreleng-actions/sigul-docker-k8s, for the containerised signing
# infrastructure deployed from that repository's Helm charts.
# linux/amd64 and linux/arm64.
#
# This file is never built. The action reads the image reference from
# the FROM line at run time, and Dependabot's docker ecosystem keeps
# the tag and digest current (.github/dependabot.yml). The testing
# workflow runs the container-side scripts inside whatever this pins,
# so a bump is exercised before it can reach a caller.
FROM ghcr.io/lfreleng-actions/sigul-docker-k8s/client:v2.6.7@sha256:c1e513281090b5b2d1db8ed3ea03ac3f76850f0b68aa1217d54f89e0fde08610
