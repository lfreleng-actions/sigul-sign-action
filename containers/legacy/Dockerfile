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
FROM docker.io/lfreleng/sigul:0.2.1@sha256:52773d955ce179b5091b2fb495d95fa584e39380083d7c8449b111627fd02753
