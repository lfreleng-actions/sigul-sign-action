# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Pin for the 'legacy' Sigul client: sigul 0.207 on CentOS 7, built by
# lfit/releng-sigul-docker, for the signing infrastructure the Linux
# Foundation runs on CentOS 7. linux/amd64 only.
#
# This file is never built. The action reads the image reference from
# the FROM line at run time, and Dependabot's docker ecosystem keeps
# the tag and digest current (.github/dependabot.yml). The testing
# workflow runs the container-side scripts inside whatever this pins,
# so a bump is exercised before it can reach a caller.
FROM docker.io/lfreleng/sigul:0.2.0@sha256:e9e1b58f0c0096c1de93dbc6ac885877f13bc6d8398f66386f34d3b7717c8f50
