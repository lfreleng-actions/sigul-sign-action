<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🔏 Sigul Sign Action

Signs artefacts or a git tag using a [Sigul][sigul] signing server.

Sigul keeps the private key on a server the client never sees. The client
sends data to a bridge, the bridge relays it to the server, and a signature
comes back. **This action never holds a signing key.**

## Migrating from `lfit/sigul-sign-action`

This action is a drop-in replacement for [`lfit/sigul-sign-action`][legacy].
Its inputs keep their names and behaviour, so a workflow migrates by changing
the `uses:` line and nothing else:

```yaml
- uses: lfreleng-actions/sigul-sign-action@<commit-sha> # vX.Y.Z
  with:
    sign-type: "sign-data"
    sign-object: artifacts/mypackage.tar.gz
    sigul-key-name: ${{ secrets.SIGUL_KEY }}
    sigul-ip: ${{ secrets.SIGUL_IP }}
    sigul-uri: ${{ secrets.SIGUL_URI }}
    sigul-conf: ${{ secrets.SIGUL_CONF }}
    sigul-pass: ${{ secrets.SIGUL_PASS }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}
```

Every input added here is optional, and the defaults reproduce the legacy
action, including the 2.0.0 release's fixes. Jenkins jobs need no change:
`global-jjb` signs with its own scripts and never calls either action.

## Choosing the Sigul client

The Linux Foundation runs two generations of Sigul, whose protocols differ.
The client must match the infrastructure holding the key, so the action
chooses it explicitly:

<!-- markdownlint-disable MD013 -->

| `container` | Client image                                                  | Sigul | Platforms              |
| ----------- | ------------------------------------------------------------- | ----- | ---------------------- |
| `legacy`    | `docker.io/lfreleng/sigul`, from [`releng-sigul-docker`][rsd] | 0.207 | `linux/amd64`          |
| `modern`    | `ghcr.io/lfreleng-actions/sigul-docker-k8s/client`            | 1.4   | `linux/amd64`, `arm64` |

<!-- markdownlint-enable MD013 -->

- **Nothing set** selects `legacy`, which the current infrastructure needs.
  Once a project's keys move to the containerised stack, its workflows add
  `container: modern`.
- **A bespoke image** goes in `container-image`, with `container-tag`,
  `container-digest` or both, in place of `container`. The action refuses an
  image with neither tag nor digest, rather than assume `latest`.
- **`container` with any `container-*` input** stops the action. Use one or
  the other, never both.

`containers/legacy/Dockerfile` and `containers/modern/Dockerfile` pin both
built-in images by tag and digest. The action reads the `FROM` line and never
builds them. Dependabot proposes each new release after a seven-day cooldown,
and the tests run inside the proposed image before it can reach a caller.

## Usage

### Sign a Maven repository

A directory signs every file beneath it, less `exclude-globs`:

```yaml
- uses: lfreleng-actions/sigul-sign-action@<commit-sha> # vX.Y.Z
  id: sign
  with:
    sign-object: m2repo
    sigul-key-name: ${{ secrets.SIGUL_KEY }}
    sigul-conf: ${{ secrets.SIGUL_CONF }}
    sigul-pass: ${{ secrets.SIGUL_PASS }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}

- run: echo "Signed ${{ steps.sign.outputs.signed_count }} files"
```

### Sign and push a git tag

```yaml
- uses: lfreleng-actions/sigul-sign-action@<commit-sha> # vX.Y.Z
  with:
    sign-type: "sign-git-tag"
    sign-object: "v1.2.3"
    gh-key: ${{ secrets.GHA_TOKEN }}
    sigul-key-name: ${{ secrets.SIGUL_KEY }}
    sigul-conf: ${{ secrets.SIGUL_CONF }}
    sigul-pass: ${{ secrets.SIGUL_PASS }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}
```

The tag must be an annotated tag. As with the legacy action, the action
fetches it first, without credentials, from the repository it pushes to; a
fetched tag replaces the local one. It then records the signed tag in the
workspace and force-pushes it to `refs/tags/<tag>`. Set `push-tag: false` to
sign without pushing, for example in a lane with no permission to publish.

### Sign against the containerised infrastructure

```yaml
- uses: lfreleng-actions/sigul-sign-action@<commit-sha> # vX.Y.Z
  with:
    container: modern
    sign-object: dist
    sigul-key-name: ${{ secrets.SIGUL_KEY }}
    sigul-conf: ${{ secrets.SIGUL_CONF }}
    sigul-pass: ${{ secrets.SIGUL_PASS }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}
```

### Check a configuration without signing

```yaml
- uses: lfreleng-actions/sigul-sign-action@<commit-sha> # vX.Y.Z
  with:
    dry-run: "true"
    sign-object: dist
    # ... credentials as above
```

A dry run does everything short of signing:

1. validates every input and resolves the files or tag;
2. pulls the client image;
3. decrypts and unpacks the credentials;
4. has the Sigul client's own code load the configuration, open the NSS
   database with its password, and find the client certificate and its key,
   checking the certificate's validity dates;
5. resolves the bridge's hostname, honouring any hosts entry;
6. checks every file is readable and its signature's directory writable, or
   that the tag resolves.

It signs nothing, pushes nothing, and changes no file in the workspace.
It never connects to the bridge either: a Sigul bridge serves clients through
a serial accept loop, and a bare connection disturbs it. A real signing run
is what proves the bridge reachable.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name                | Default             | Description                                                                              |
| ------------------- | ------------------- | ---------------------------------------------------------------------------------------- |
| `sign-type`         | `sign-data`         | `sign-data` or `sign-git-tag`                                                            |
| `sign-object`       |                     | **Required.** Files to sign, one per line; or the tag to sign                            |
| `sigul-key-name`    |                     | **Required.** Name of the signing key on the server                                      |
| `sigul-conf`        |                     | **Required.** Body of the client configuration, `client.conf`                            |
| `sigul-pass`        |                     | **Required.** Key passphrase, which also decrypts `sigul-pki`; Sigul gets its first line |
| `sigul-pki`         |                     | **Required.** GPG-encrypted `tar.xz` of the NSS database, ASCII-armoured or base64       |
| `sigul-ip`          |                     | Bridge IP address, for the hosts entry                                                   |
| `sigul-uri`         |                     | Bridge hostname, for the hosts entry                                                     |
| `gh-user`           | `github.actor`      | User to push a signed tag as                                                             |
| `gh-key`            |                     | Token to push a signed tag. Required for `sign-git-tag` unless `push-tag` is `false`     |
| `container`         | `legacy` when unset | Built-in client: `legacy` or `modern`                                                    |
| `container-image`   |                     | Bespoke client image, in place of `container`                                            |
| `container-tag`     |                     | Tag for `container-image`                                                                |
| `container-digest`  |                     | Digest for `container-image`, as `sha256:<64 hex digits>`                                |
| `sigul-hosts-entry` | `auto`              | `auto` adds the hosts entry for `legacy`; `true` for any container; `false` never        |
| `push-tag`          | `true`              | Push a signed tag back to the repository                                                 |
| `dry-run`           | `false`             | Check everything, sign nothing                                                           |
| `exclude-globs`     | `global-jjb`'s list | File name patterns skipped inside a directory                                            |
| `max-retries`       | `5`                 | Attempts per signing operation                                                           |
| `retry-delay`       | `15`                | Seconds between attempts                                                                 |

<!-- markdownlint-enable MD013 -->

The default `exclude-globs` is `global-jjb`'s:

```text
*.asc  *.md5  *.sha1
_maven.repositories  _remote.repositories
*.lastUpdated  maven-metadata.xml  maven-metadata-local.xml
```

It does not exclude `*.sha256` or `*.sha512`: `global-jjb` signs those, and
omitting them would change what a migrated release publishes.

## Outputs

<!-- markdownlint-disable MD013 -->

| Name              | Description                                                                       |
| ----------------- | --------------------------------------------------------------------------------- |
| `signed_count`    | Files signed; `0` for `sign-git-tag`, which signs a tag object, and for a dry run |
| `container_image` | The client image used, by digest                                                  |

<!-- markdownlint-enable MD013 -->

## What `sign-object` signs

For `sign-data`, one entry per line, with blank lines ignored:

- **A line containing `*`** splits into words, and each word expands as a
  shell wildcard. Every regular file it matches gets a signature, a symlink to
  one included; a line matching nothing produces a warning.
- **A file** gets a signature.
- **A directory** signs every regular file beneath it, less `exclude-globs`,
  as `global-jjb`'s `sigul-sign-dir.sh` did, passing over symlinks and special
  files. The legacy action could not sign a directory.

Each signature lands beside its file, with `.asc` appended: beside a symlink,
not its target. Every path must resolve inside the workspace, as with the
legacy action, whose container could reach nothing else. A path the legacy
container saw as `/github/workspace/...` still works.

The step fails when any entry names no file or directory, when nothing gets
signed, or when any file fails to sign. Before signing, the action removes the
signatures this run will write, so a failed run never leaves an earlier run's
signature behind for a file in `sign-object`.

## Credentials

Three inputs carry Sigul credentials: `sigul-conf`, `sigul-pass` and
`sigul-pki`. `gh-key` is a secret too, a GitHub token that `sign-git-tag`
needs to push. `sigul-key-name` names a key rather than containing one.

- **`client.conf` travels verbatim from Jenkins.** The action locates the NSS
  database in the unpacked bundle by its file names (`cert8.db`, `cert9.db`,
  `key3.db`, `key4.db`, `secmod.db` or `pkcs11.txt`), and rewrites `nss-dir`
  to match. ONAP's `/home/jenkins/sigul` needs no editing.
- **Fill in Jenkins' placeholders first.** Jenkins' managed `sigul-config` is a
  template: `$SIGUL_CONFIG_USR` and `$SIGUL_CONFIG_PSW` come from the
  `sigul-config-credentials` credential when Jenkins provides the file. A copy
  taken from the managed-files page still holds them, and the action refuses
  it with an explanation.
- **A bundle's own `.sigul/client.conf` still applies.** As with the legacy
  action, it overrides `sigul-conf` wherever both set a value.
  `sigul_setup_client` keeps `nss-password` there.
- **Decryption and Sigul both use the first line of `sigul-pass`**, so a
  secret stored with a trailing newline works as before.

### The hosts entry

The legacy action wrote `sigul-ip` and `sigul-uri` into the container's
`/etc/hosts`. The `legacy` container still gets that entry by default, so
existing workflows behave as before. Any other container gets it with
`sigul-hosts-entry: true`: the containerised infrastructure has public DNS.

The action warns when `sigul-ip` differs from what DNS gives for `sigul-uri`.
The `SIGUL_BRIDGE_IP` values some projects keep in their Jenkins
configuration now name addresses the bridges no longer use, and a hosts entry
built from one would send signing nowhere.

### Handling

- The validation step never receives a credential, so a misconfigured call
  fails before any secret reaches the disk.
- Secrets live in a mode-0700 directory. On every exit path, cancellation
  included, the action overwrites each file that held one before removing
  it, without depending on `shred`; like `shred`, that cannot reach copies a
  copy-on-write or journalling filesystem keeps. A composite action has no
  post step, so the step that creates them removes them.
- The client container receives them as files: no secret appears on any
  command line, in any environment, or in `docker inspect`. The signing step
  hands them to a fresh process image through an anonymous in-memory file,
  with no name on any filesystem, and re-executes without them: no process,
  the step's own included, keeps them in its environment while signing runs.
- `gpg` decrypts in a private home, removed afterwards, with its agent stopped
  and passphrase caching off; the runner's own keyring stays untouched.
- The container runs as the runner's own user, with every capability dropped,
  and the workflow owns the signatures and git objects it produces.
- `sign-git-tag` never runs git against the workspace repository, whose
  configuration the calling job controls. It signs in a private repository
  that keeps its objects in the workspace's object store, records the result
  by writing a ref file, and pushes with the token supplied by a credential
  helper scoped to the server.

## Requirements

- **A Linux runner with Docker**, rootful or rootless. The action refuses a
  daemon that remaps user namespaces (`userns-remap`): no container user there
  is the runner's own. The legacy client needs `linux/amd64`; the modern
  client also runs on `linux/arm64`.
- **Python 3.10.12, 3.11.4, 3.12 or later**, for `tarfile`'s `data`
  extraction filter. The action refuses to unpack key material without it.
  Every current GitHub-hosted runner image qualifies.
- **`python3`, `docker`, `git` and `gpg` in the system's own directories**:
  Debian's and Ubuntu's default `PATH` of `/usr/local/bin`, `/usr/bin`,
  `/bin`, their `sbin` siblings and `/snap/bin`. The action never runs a tool
  from the job's `PATH`, to which an earlier step could add one that would
  receive the credentials.
- **Network access to the bridge**, on port 44334:

<!-- markdownlint-disable MD013 -->

| Bridge                                       | Infrastructure | Projects                  |
| -------------------------------------------- | -------------- | ------------------------- |
| `sigul-bridge-yul.linuxfoundation.org`       | Legacy         | ONAP, OpenDaylight, EdgeX |
| `sigul-bridge-us-west-2.linuxfoundation.org` | Legacy         | O-RAN-SC, DENT            |
| `sigul-bridge.opensearch.org`                | Modern         | OpenSearch                |

<!-- markdownlint-enable MD013 -->

The organisation's harden-runner allow-list carries these, for jobs running in
`block` mode.

## Testing

CI never contacts a bridge. It tests in three layers:

- **Unit tests** cover every input rule, the credential handling against real
  GPG-encrypted bundles, and the git handling against throwaway repositories,
  under Python 3.10 and 3.12.
- **Validation** runs the action against inputs it must refuse.
- **End-to-end** runs the action once per client image and architecture, with
  credentials made by each image's own `certutil`:
  - dry runs inside the real pinned images, whose own Sigul code loads the
    configuration and opens the NSS database;
  - real signing runs inside a test image, the pinned image with a mock
    `sigul` added, served from a local registry as a bespoke image;
  - credentials the action must refuse.

The **Live signing** workflow covers the rest. Run it by hand to sign a
throwaway file or tag against real infrastructure, with real credentials; the
dry run is on by default. It reads its secrets from the `sigul-legacy` or
`sigul-modern` environment, under the names the comment at the top of
`.github/workflows/live-signing.yaml` lists.

## Layout

- `action.yaml` holds the inputs and two steps: a check, then signing.
- `scripts/` holds the Python that runs on the runner.
- `scripts/container/` runs inside the client image. It stays valid under
  Python 2.7, which the legacy image ships, as well as Python 3.
- `containers/` holds the pinned client images.

[sigul]: https://pagure.io/sigul
[legacy]: https://github.com/lfit/sigul-sign-action
[rsd]: https://github.com/lfit/releng-sigul-docker
