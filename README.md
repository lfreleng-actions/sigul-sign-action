<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🔏 Sigul Sign Action

Signs artefacts or a git tag using a [Sigul][sigul] signing server.

Sigul keeps the private key on a server the client never sees. The client
sends data to a bridge, the bridge relays it to the server, and a detached
signature comes back. **This action never holds a signing key.**

It replaces `global-jjb`'s `sigul-sign-dir.sh` and `sigul-sign-git-tag.sh`,
reproducing their behaviour for workflows migrating off Jenkins.

## Two backends, one interface

The Linux Foundation runs two generations of Sigul infrastructure:

<!-- markdownlint-disable MD013 -->

| Backend  | Version | State                                                      |
| -------- | ------- | ---------------------------------------------------------- |
| `legacy` | 0.207   | Deployed; serves production releases today                 |
| `k8s`    | 1.4     | Containerised, via [`sigul-docker-k8s`][k8s]; not yet live |

<!-- markdownlint-enable MD013 -->

The protocol differs between them, so `backend` is an **explicit input**
rather than something detected at runtime. A signing step that picks the
wrong backend without saying so either fails confusingly or succeeds against
infrastructure the caller did not intend to use.

`backend: k8s` is a valid value that **fails with a clear error** until the
migration completes, so workflows can name it now and cannot fall back to the
wrong server unnoticed.

## Usage

### Sign a Maven repository before staging

```yaml
- name: "Sign artefacts"
  id: sign
  uses: lfreleng-actions/sigul-sign-action@<sha>
  with:
    mode: "directory"
    path: "m2repo"
    sigul-key: ${{ vars.SIGUL_KEY }}
    sigul-config: ${{ secrets.SIGUL_CONFIG }}
    sigul-password: ${{ secrets.SIGUL_PASSWORD }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}

- run: echo "Signed ${{ steps.sign.outputs.signed_count }} artefacts"
```

### Sign a git tag

```yaml
- name: "Sign the release tag"
  uses: lfreleng-actions/sigul-sign-action@<sha>
  with:
    mode: "git-tag"
    git-tag: "v1.2.3"
    sigul-key: ${{ vars.SIGUL_KEY }}
    sigul-config: ${{ secrets.SIGUL_CONFIG }}
    sigul-password: ${{ secrets.SIGUL_PASSWORD }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}
```

The tag must already exist and be **annotated**. The action signs it in place
and **does not push**: pushing needs a different privilege, differs between
GitHub and Gerrit, and belongs to the release lane. `global-jjb` couples the
two; separating them lets a verify lane sign a tag with no ability to publish
it.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name              | Required | Default           | Description                                                           |
| ----------------- | -------- | ----------------- | --------------------------------------------------------------------- |
| `mode`            | Yes      |                   | `directory`, `file` or `git-tag`                                      |
| `path`            | Cond.    |                   | Target for `directory` and `file` modes                               |
| `git-tag`         | Cond.    |                   | Existing annotated tag, for `git-tag` mode                            |
| `repository-path` | No       | `.`               | Repository directory for `git-tag` mode                               |
| `backend`         | No       | `legacy`          | `legacy` or `k8s`                                                     |
| `sigul-key`       | Yes      |                   | Key name held on the Sigul server                                     |
| `sigul-config`    | Yes      |                   | Body of the Sigul `client.conf`                                       |
| `sigul-password`  | Yes      |                   | Key passphrase; also decrypts `sigul-pki`                             |
| `sigul-pki`       | Yes      |                   | GPG-encrypted `tar.xz` of the NSS database; raw or base64             |
| `exclude-globs`   | No       | Maven bookkeeping | Newline-separated `find -name` patterns to skip, for `directory` mode |
| `max-retries`     | No       | `5`               | Attempts per signing operation                                        |
| `retry-delay`     | No       | `15`              | Seconds between attempts                                              |
| `legacy-image`    | No       | pinned by digest  | Sigul client image for the `legacy` backend                           |
| `k8s-image`       | No       | ghcr client image | Sigul client image for the `k8s` backend                              |

<!-- markdownlint-enable MD013 -->

The default `exclude-globs` reproduces `global-jjb`'s list:

```text
*.asc  *.md5  *.sha1
_maven.repositories  _remote.repositories  *.lastUpdated
maven-metadata.xml  maven-metadata-local.xml
```

Note it does **not** exclude `*.sha256` or `*.sha512`. `global-jjb` signs
those, and omitting them here would change what a migrated release publishes
without anyone noticing. Set `exclude-globs` to an empty string to sign every file.

## Outputs

<!-- markdownlint-disable MD013 -->

| Name           | Description                                                                        |
| -------------- | ---------------------------------------------------------------------------------- |
| `signed_count` | Files signed. Always `1` for `file` mode, `0` for `git-tag`, which signs an object |
| `backend`      | Backend actually used                                                              |

<!-- markdownlint-enable MD013 -->

## Credentials

Four inputs. **Three carry secrets** — `sigul-config`, `sigul-password` and
`sigul-pki` — conventionally sourced from 1Password by the caller.
`sigul-key` names a key rather than containing one, so a repository variable
suits it.

<!-- markdownlint-disable MD013 -->

| Input            | Shape                                                       |
| ---------------- | ----------------------------------------------------------- |
| `sigul-key`      | Plain string; not secret, so a repository variable suits it |
| `sigul-config`   | Multi-line `client.conf` text                               |
| `sigul-password` | Passphrase                                                  |
| `sigul-pki`      | Binary `tar.xz`, GPG-encrypted, base64 tolerated            |

<!-- markdownlint-enable MD013 -->

The action writes the three secrets to a mode-0700 temporary directory, mounts
that into the container, and removes it through a shell **trap that fires on
every exit path including failure**. A composite action cannot declare a post
step, so cleanup lives inside the step that created the material — doing it in
a later step would leave credentials on disk whenever signing failed.

Container arguments carry **paths** for the three secrets, so none appears in
the process table or in `docker inspect`. `sigul-key` travels by value, being
a key name rather than a key.

The container runs as the **runner's own UID/GID**. The pinned image declares
no `USER`, so it would otherwise run as root and leave every `.asc` file and
rewritten git object root-owned, breaking later non-root steps.

### The `client.conf` needs no editing

A `client.conf` carries an absolute `nss-dir` naming wherever the NSS database
sat on its originating machine. ONAP's says:

```ini
nss-dir: /home/jenkins/sigul
```

That path does not exist inside the container, and the directory name **inside
the bundle varies between deployments** — ONAP's unpacks to `sigul/`, while
other Sigul tooling documents `.sigul/`.

Rather than require one layout, the action unpacks the bundle, locates the NSS
database by its contents (`cert8.db`, `cert9.db`, `key3.db`, `key4.db`,
`secmod.db` or `pkcs11.txt`), and rewrites `nss-dir` to the real in-container
path, logging both. A `client.conf` thus travels **verbatim from Jenkins**
with no editing.

A bundle containing no NSS database fails with its directory structure listed,
rather than surfacing later as a confusing certificate error.

## Requirements

- **Docker** on the runner. Sigul 0.x needs Python 2 and an NSS stack no
  current runner image ships, so the client runs in a container.
- **Python 3.12 or later** on the runner. Credential materialisation unpacks
  the PKI bundle through `tarfile`'s `data` extraction filter, which arrived
  in 3.12; the action refuses to run without it rather than falling back to a
  weaker containment check. Every current runner image satisfies this.
- **`gpg`** on the runner, to decrypt the bundle. A missing `gpg` reports
  itself rather than appearing as a decryption failure.

Note that `tar` and `base64` are **not** required as executables: the action
uses Python's `tarfile` and `base64` modules.

- **`linux/amd64`.** The published Sigul client image installs an x86_64 RPM
  and ships single-platform, so the `legacy` backend cannot run on an arm64
  runner. The action checks this and fails with the reason rather
  than letting Docker report an exec format error.
- **Network reach to the Sigul bridge.** For ONAP that is
  `sigul-bridge-yul.linuxfoundation.org:44334`, which resolves publicly, so
  GitHub-hosted runners work without a VPN. Add it to the harden-runner
  allow-list when running with `egress-policy: block`.

## Design notes

**Python, with a portability constraint.** The runner-side credential work is
modern Python 3. The two container entrypoints are valid under **both** Python
2.7 and 3.x by design: the legacy Sigul image is CentOS 7 and ships Python
2.7 with no `python3`, while the containerised 1.4 stack is Fedora-based and
ships `python3` with no bare `python`. One source file serves both, so there
is no second implementation to keep in step — the action selects the
interpreter from `backend`. When the legacy infrastructure retires, the change
is deleting two `__future__` imports and a `per-file-ignores` entry.

That constrains those two files: no f-strings, no `pathlib`, no
`subprocess.run`, no annotations. `.ruff.toml` records why.

**The scripts live here.** `global-jjb`'s `sigul-sign-dir.sh` `wget`s
`sigul-sign.sh`, `sigul-sign-git-tag.sh` and a `Dockerfile` from
`releng-global-jjb` **master** on every run, so pinning `global-jjb` does not
pin the code that signs releases. This action mounts `scripts/` from its own
pinned checkout.

**No image build at sign time.** `global-jjb` builds a `Dockerfile` whose sole
purpose is to `COPY` two scripts into a published base image. Mounting them
achieves the same thing and removes a build from the release path.

**One container run for a whole tree.** The earlier action signed one
`sign-object` per invocation, which means a container start per artefact —
unusable for an `m2repo` of hundreds of files.

**Credentials mount read-write.** NSS creates lock files in its database
directory, and a mount without write access fails with a certificate error
resembling a bad credential. The directory is a per-run temporary one that
the trap
destroys.

**Retries.** The client crosses a network to the bridge; a transient error
should
not fail a release. `global-jjb` retried tag signing but not artefact signing.

## Testing

Two layers, because CI has no access to a signing server:

- **Input validation** calls the action itself across every rejection path.
  These reach no credential and no network.
- **Script tests** run the container entrypoints with a mock `sigul` on
  `PATH`, covering file selection, exclusions, retry, the count, and the
  refusal to sign nothing.

What remains untested is the container invocation — image pull, mounts,
credential materialisation. That needs real credentials, and the first live
signing run will confirm it.

[sigul]: https://pagure.io/sigul
[k8s]: https://github.com/lfreleng-actions/sigul-docker-k8s
