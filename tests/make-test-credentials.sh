#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Build throwaway Sigul client credentials for testing the action.
#
# The NSS database and client certificate are made by the client
# image's own certutil, so the database is in the format that image's
# NSS reads; the bundle is then packed and encrypted the way a real
# one is: a tar.xz, symmetrically GPG-encrypted, ASCII-armoured.
# Nothing here can sign anything: no Sigul server knows the key.
#
# Usage: make-test-credentials.sh IMAGE PLATFORM OUT_DIR LAYOUT DB_TYPE
#
#   LAYOUT   'sigul'   ONAP's layout: the database in sigul/, and the
#                      NSS password in client.conf
#            '.sigul'  the sigul_setup_client layout: the database and
#                      a client.conf holding the NSS password, both in
#                      .sigul/, which the action layers over client.conf
#   DB_TYPE  'dbm' (cert8.db, as the legacy bundles use) or 'sql'
#
# Writes OUT_DIR/client.conf, OUT_DIR/pki.asc and OUT_DIR/passphrase.
# The bridge is named sigul-bridge.test on the default port.

set -euo pipefail

image="$1"
platform="$2"
out="$3"
layout="$4"
db_type="$5"

case "${layout}" in
    sigul | .sigul) ;;
    *) echo "LAYOUT must be 'sigul' or '.sigul'" >&2; exit 2 ;;
esac
case "${db_type}" in
    dbm | sql) ;;
    *) echo "DB_TYPE must be 'dbm' or 'sql'" >&2; exit 2 ;;
esac

passphrase="sigul-test-passphrase"
nss_password="nss-test-password"

mkdir -p "${out}"
# A short path: gpg-agent's socket lives in the gpg home, and a Unix
# socket path is limited to around 100 characters.
build="$(mktemp -d /tmp/sigul-test.XXXXXX)"
trap 'rm -rf "${build}"' EXIT
mkdir -p "${build}/bundle/${layout}"
printf '%s\n' "${nss_password}" > "${build}/nss-password"

docker run --rm --platform "${platform}" \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=${build},target=/build" \
    --entrypoint /bin/sh "${image}" -c '
        set -eu
        db="$1:/build/bundle/$2"
        head -c 1024 /dev/urandom > /build/noise
        certutil -N -d "${db}" -f /build/nss-password
        certutil -S -x -n sigul-client-cert -s "CN=sigul-action-test" \
            -t "CT,C,C" -d "${db}" -f /build/nss-password \
            -z /build/noise >/dev/null
    ' make-test-credentials "${db_type}" "${layout}"

{
    printf '[client]\n'
    printf 'bridge-hostname: sigul-bridge.test\n'
    printf 'bridge-port: 44334\n'
    printf 'client-cert-nickname: sigul-client-cert\n'
    printf 'server-hostname: sigul-server.test\n'
    printf 'user-name: sigul-action-test\n'
    printf '\n[nss]\n'
    # The Jenkins path ONAP's configuration carries; the action
    # rewrites it to wherever the bundle unpacks.
    printf 'nss-dir: /home/jenkins/sigul\n'
    if [ "${layout}" = "sigul" ]; then
        printf 'nss-password: %s\n' "${nss_password}"
    fi
} > "${out}/client.conf"

if [ "${layout}" = ".sigul" ]; then
    printf '[nss]\nnss-password: %s\n' "${nss_password}" \
        > "${build}/bundle/.sigul/client.conf"
fi

tar -C "${build}/bundle" -cJf "${build}/pki.tar.xz" "${layout}"
printf '%s\n' "${passphrase}" > "${out}/passphrase"
gpg --homedir "${build}" --batch --yes --quiet --pinentry-mode loopback \
    --passphrase-file "${out}/passphrase" --armor --symmetric \
    --output "${out}/pki.asc" "${build}/pki.tar.xz"

echo "Test credentials (${layout}, ${db_type}) written to ${out}"
