<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🔏 Sigul Sign Action

Signs artefacts or a git tag using a [Sigul][sigul] signing server.

Sigul keeps the artefact-signing private key on the server. The client sends
data through a bridge and receives a signature. **The action does hold the
NSS client-authentication private key locally.** That credential and the key
passphrase can authorise signing requests; protect them even though the
artefact-signing private key never leaves the server.

## Migrating from `lfit/sigul-sign-action`

The input names from [`lfit/sigul-sign-action`][legacy] remain, but this is
**not an unconditional drop-in replacement**. The default client selection
is still `legacy`, but `allow-legacy` defaults to `false`. Every built-in
legacy run, including a dry run, requires `allow-legacy: "true"`.

Before opting in, get an approved, time-bounded risk exception with a
named owner and a retirement or migration date, and use an isolated signing
runner. The opt-in accepts the unsupported CentOS 7/Python 2 client's risk;
it does not make that client supported or secure.

For an approved legacy exception, the migrated call looks like this:

```yaml
- uses: lfreleng-actions/sigul-sign-action@<commit-sha> # vX.Y.Z
  with:
    container: legacy
    allow-legacy: "true" # Requires an approved risk exception
    sign-type: "sign-data"
    sign-object: artifacts/mypackage.tar.gz
    sigul-key-name: ${{ secrets.SIGUL_KEY }}
    sigul-ip: ${{ secrets.SIGUL_IP }}
    sigul-uri: ${{ secrets.SIGUL_URI }}
    sigul-conf: ${{ secrets.SIGUL_CONF }}
    sigul-pass: ${{ secrets.SIGUL_PASS }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}
```

Migration also requires a patched, supported host runtime, authenticated
credential encryption, and bundles and checkouts that meet the stricter
validation rules below. Review [Credentials](#credentials) and
[Requirements](#requirements) before use. Jenkins jobs need no change:
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

- **Nothing set** selects `legacy`, but validation rejects it unless
  `allow-legacy: "true"`. Once a project's keys move to the containerised
  stack, its workflows can select `container: modern`. A modern client is
  not a protocol-compatible substitute for legacy infrastructure.
- **A bespoke image** goes in `container-image`, with `container-tag`,
  `container-digest` or both, in place of `container`. The action refuses an
  image with neither tag nor digest, rather than assume `latest`.
- **`container` with any `container-*` input** stops the action. Use one or
  the other, never both.

Every `PATH` entry in a bespoke image must name a nonempty absolute
location. `SIGULPATH` must also be absolute if the image sets it. The entrypoint
refuses relative tool lookup before starting any interpreter or Sigul subprocess.
It preserves image-specific absolute directories and uses the same resolved
interpreter for probing and execution.

`containers/legacy/Dockerfile` and `containers/modern/Dockerfile` pin both
built-in images by tag and digest. The action reads the `FROM` line and never
builds them. Dependabot proposes release updates after a seven-day cooldown;
the test workflow exercises the proposed images, not real-server signing.
Neither pinning nor a passing smoke test certifies their dependencies.

As of **8 October 2026**, the modern pin remains `v2.6.1`, with digest
`sha256:07e89d1322cf8e2ac4e33103d964982a96d1e0c7fe8ba55cd1e988e7a51ba502`.
`v2.6.2` remains a draft release; upstream has not published a newer fixed
modern image.
Known dependency work remains: `openssl-libs` 3.5.8 needs 3.5.9, and pip's
vendored `urllib3` 2.7 needs 2.8. Updating a separate `urllib3` installation
does not update pip's bundled copy. **Dependency remediation is incomplete.**

An external image rebuild and publication, followed by a reviewed digest
update and rescan of the supported architectures, remain production
prerequisites for the modern client. A bespoke image needs its own dependency
and protocol review. The legacy image remains an unsupported exception with
an owner and retirement plan, not a security-maintained fallback.

## Usage

Replace `<commit-sha>` with a reviewed full commit SHA. The legacy examples
assume the approved risk exception above; all production use also needs the
[production prerequisites](#production-prerequisites).

### Sign a Maven repository

A directory signs every file beneath it, less `exclude-globs`:

```yaml
- uses: lfreleng-actions/sigul-sign-action@<commit-sha> # vX.Y.Z
  id: sign
  with:
    container: legacy
    allow-legacy: "true"
    sign-object: m2repo
    sigul-key-name: ${{ secrets.SIGUL_KEY }}
    sigul-conf: ${{ secrets.SIGUL_CONF }}
    sigul-pass: ${{ secrets.SIGUL_PASS }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}

- run: echo "Signed ${{ steps.sign.outputs.signed_count }} files"
```

### Sign a git tag for publication

Keep automatic pushing off so a later step can verify the signature against
the expected public key before publishing:

```yaml
- uses: lfreleng-actions/sigul-sign-action@<commit-sha> # vX.Y.Z
  with:
    container: legacy
    allow-legacy: "true"
    sign-type: "sign-git-tag"
    sign-object: "v1.2.3"
    push-tag: "false"
    sigul-key-name: ${{ secrets.SIGUL_KEY }}
    sigul-conf: ${{ secrets.SIGUL_CONF }}
    sigul-pass: ${{ secrets.SIGUL_PASS }}
    sigul-pki: ${{ secrets.SIGUL_PKI }}
```

Use an annotated tag whose original payload ends with a newline.
The action fetches it first, without credentials, from the repository URL
it would push to; a fetched tag takes precedence over the workspace copy.
The structural check requires the original tag bytes followed by one
complete, nonempty ASCII-armoured PGP signature block. It preserves payload bytes,
including line endings and any earlier signature. These are structural
checks, not cryptographic verification.

The action records the signed tag in the workspace. Its default,
`push-tag: true`, also pushes it: this requires `gh-key` and an explicit
expected-object-ID lease for `refs/tags/<tag>`. The lease requires a
successful anonymous fetch of that tag from the same URL in this run. A
concurrent remote replacement or deletion causes the push to fail. A failed
fetch permits signing the workspace tag without a push, but never
authorises publication; a run requesting a push fails without that lease.
A failed push can leave the signed local tag in place.

For production, use `push-tag: "false"`, verify the result, then publish in a
separate step that retains the same remote-observation and expected-ID lease
requirements. Automatic pushing does not provide that verification gate.

The workspace must be a standard checkout, as `actions/checkout` makes one:
`.git` a directory with its own object store, refs kept as files, and SHA-1
object names. Linked worktrees, submodule checkouts, symlinked `.git` or
`.git/objects`, borrowed object stores, configuration includes, reftables,
SHA-256 object names, and unknown ref-storage or object-format settings are
not supported.

For automatic pushing, `gh-key` needs write access to the repository's
contents: `contents: write` for the job's `GITHUB_TOKEN`, or a personal access
token or GitHub App token
that grants the same. A tag pushed with `GITHUB_TOKEN` starts no other
workflow, by GitHub's rule against recursive runs, so a release workflow that
should run on the signed tag needs a token of its own, as with the legacy
action.

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
    container: modern
    dry-run: "true"
    sign-object: dist
    # ... credentials as above
```

For legacy infrastructure, select `container: legacy` and set
`allow-legacy: "true"` under the approved exception even for a dry run.

A dry run:

1. validates public input structure and credential presence, plans file
   targets, or checks the tag name and checkout layout;
2. checks data-output directory permissions on the host and pulls the image;
3. decrypts and validates the credential archive, and resolves an annotated
   tag in a private repository when signing a tag;
4. has the Sigul client's own code load the configuration, open the NSS
   database with its password, and find the client certificate and its key,
   checking the certificate's validity dates;
5. resolves the bridge's hostname, honouring any hosts entry;
6. checks file readability and output-directory presence inside the client,
   or that the tag resolves there.

A data dry run uses a `readonly` workspace bind mount. The probe opens source
files for reading; it does not test writes. The host permission preflight is not
proof of container write access: UID mapping, supplementary groups and ACLs
can differ. A tag dry run uses a private object store and reads the workspace
store without writing to it, even when fetching the tag.

A dry run signs nothing, pushes nothing, and changes no workspace files. It
still decrypts real credentials and runs the selected image, so it requires
the same trust and isolation as signing. It never connects to the bridge:
a Sigul bridge serves clients through a serial accept loop, and a bare
connection disturbs it. A non-dry live run with independent signature
verification must establish bridge/server access, key authorisation and a
valid returned signature.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name                | Default             | Description                                                                                                  |
| ------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------ |
| `sign-type`         | `sign-data`         | `sign-data` or `sign-git-tag`                                                                                |
| `sign-object`       |                     | **Required.** Files to sign, one per line, or a directory; or the tag to sign                                |
| `sigul-key-name`    |                     | **Required.** Name of the signing key on the server                                                          |
| `sigul-conf`        |                     | **Required.** Body of the client configuration, `client.conf`                                                |
| `sigul-pass`        |                     | **Required.** Key passphrase, which also decrypts `sigul-pki`; Sigul gets its first line                     |
| `sigul-pki`         |                     | **Required.** GPG-encrypted `tar.xz` of the NSS database, ASCII-armoured or base64                           |
| `sigul-ip`          |                     | Bridge IP address, for the hosts entry                                                                       |
| `sigul-uri`         |                     | Bridge hostname, for the hosts entry                                                                         |
| `gh-user`           | `github.actor`      | User to push a signed tag as                                                                                 |
| `gh-key`            |                     | Token to push a signed tag, with `contents: write`. Required for `sign-git-tag` unless `push-tag` is `false` |
| `container`         | `legacy` when unset | Built-in client: `legacy` or `modern`; legacy requires explicit opt-in                                       |
| `allow-legacy`      | `false`             | Accept the unsupported legacy client under an approved, time-bounded exception; required even for dry runs   |
| `container-image`   |                     | Bespoke client image, in place of `container`                                                                |
| `container-tag`     |                     | Tag for `container-image`                                                                                    |
| `container-digest`  |                     | Digest for `container-image`, as `sha256:<64 hex digits>`                                                    |
| `sigul-hosts-entry` | `auto`              | `auto` adds the hosts entry for `legacy`; `true` for any container; `false` never                            |
| `push-tag`          | `true`              | Push a signed tag back to the repository                                                                     |
| `dry-run`           | `false`             | Check local prerequisites without signing or contacting the bridge                                           |
| `exclude-globs`     | `global-jjb`'s list | File name patterns skipped inside a directory                                                                |
| `max-retries`       | `5`                 | Attempts per signing operation                                                                               |
| `retry-delay`       | `15`                | Seconds between attempts                                                                                     |
| `attempt-timeout`   | `600`               | Seconds one attempt may take before the action stops and retries it; `0` for no limit                        |

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

| Name                | Description                                                                         |
| ------------------- | ----------------------------------------------------------------------------------- |
| `validation_status` | Structural validation: `passed`, `rejected`, or empty if validation could not start |
| `signed_count`      | Files signed on successful completion; `0` for `sign-git-tag` and for a dry run     |
| `container_image`   | The client image used, by digest                                                    |

<!-- markdownlint-enable MD013 -->

`validation_status` reports public input structure and credential presence,
not valid credentials, a resolved tag, or successful signing.
Credential-content checks and actual tag resolution happen later in the
signing step, including a dry run. A bootstrap or runtime failure before
validation leaves it empty; a later signing failure can still have
`validation_status: passed`.

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

The action deduplicates targets by output path. It skips sources that are
also planned signature outputs, including symlink chains through those
outputs. The step fails on an invalid file or directory entry, when no
targets remain, or when any target fails to sign.

For a real run, after validation and host output-permission checks, the
action attempts to remove every planned stale signature. It tries all
outputs even if one removal fails, then aborts on any removal failure.
Validation or preflight failures can leave old signatures untouched.
Signing is sequential: successful outputs remain if a later file fails.
**This is not an atomic batch or a rollback guarantee.** Require whole-step
success and independent verification of every signature before publication.

The action allows at most `max-retries` attempts per signing operation,
`retry-delay` seconds apart, and stops an attempt after `attempt-timeout`
seconds. The Sigul client can wait forever on a silent bridge; `0` disables
the per-attempt timeout, so also set a job timeout.

## Credentials

Three inputs carry Sigul credentials: `sigul-conf`, `sigul-pass` and
`sigul-pki`. `gh-key` is a secret too, a GitHub token that `sign-git-tag`
needs to push. `sigul-key-name` names a key rather than containing one.

- **Reuse existing Jenkins configuration values.** The action locates one
  NSS database in the unpacked bundle by its file names (`cert8.db`,
  `cert9.db`, `key3.db`, `key4.db`, `secmod.db` or `pkcs11.txt`), and rewrites
  `nss-dir` to match. ONAP's `/home/jenkins/sigul` needs no path editing;
  more than one database directory causes rejection.
- **INI rewriting preserves effective values, not source text.** A raw INI
  parser handles continuations and literal percent signs, replaces the full
  `nss-dir` value, and retains the last value of duplicate options. Comments
  and formatting do not survive serialization. Malformed configurations or
  values that cannot round-trip cause rejection.
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
- **Decryption happens on the runner, with its own GnuPG.** The action
  requires machine-readable status confirming one authenticated plaintext,
  with MDC or AEAD protection, as well as a successful GPG exit. It rejects
  unprotected encryption and unencrypted `gpg --store` packets; a zero exit
  status alone is not enough. Re-encrypt old bundles with a current GnuPG
  (`gpg --symmetric --cipher-algo AES256 --armor sigul.tar.xz`) and store
  the result. The action never passes `--ignore-mdc-error`.

### Bundle format and limits

`scripts/credential_archive.py` validates the archive before creating its
contents in a fresh private directory. It copies validated regular files
and creates directories; it rejects symlinks, hardlinks, sparse files and
special files. It does not use `tarfile.extractall` or rely on extraction
filters, and it does not apply archive ownership or permission metadata.

The limits apply to dry runs too:

- Each INI configuration is at most **1 MiB**. `sigul-pki` accepts at most
  **2,097,152 input characters** and **1 MiB of ciphertext** after any outer
  base64 decoding.
- An archive has at most **256 file/directory members**, **16 MiB per file**
  and **32 MiB total expanded file contents**.
- Paths must be relative and printable, with no parent traversal,
  backslashes or leading/trailing component whitespace. Limits are
  **16 components**, **255 UTF-8 bytes per component** and **1,024 UTF-8
  bytes per path**. Duplicate normalized file paths cause rejection.
- The decrypted archive and the decompressed tar stream each have a
  **64 MiB** limit, including tar metadata. XZ decoding has a **128 MiB**
  memory limit.
- GPG decryption has a **60-second total deadline**, including compatibility
  retries. Archive processing has its own **60-second deadline**, checked
  between local I/O operations. Neither deadline can interrupt blocked
  kernel I/O.

### The hosts entry

The legacy action wrote `sigul-ip` and `sigul-uri` into the container's
`/etc/hosts`. Once legacy use has explicit approval, `auto` still adds that
entry for the built-in `legacy` client. Any other container gets it with
`sigul-hosts-entry: true`: the containerised infrastructure has public DNS.

The action warns when `sigul-ip` differs from what DNS gives for `sigul-uri`.
The `SIGUL_BRIDGE_IP` values some projects keep in their Jenkins
configuration now name addresses the bridges no longer use, and a hosts entry
built from one would send signing nowhere.

### Handling

- The validation step receives credential-presence flags, not the secret
  values. It rejects structural input errors before materializing
  credentials; it does not check credential content or certify signing.
- **The trust boundary is the job, not the step.** Every step of a job runs
  as one user, who on GitHub-hosted runners has passwordless `sudo` and the
  Docker socket, so an earlier step that means harm can always reach a later
  step's secrets. What the action does guard against is an earlier step
  redirecting it by accident, which `setup-*` actions and tool shims do: it
  ignores the job's `PATH`, `BASH_ENV`, `ENV` and the dynamic loader's
  variables, runs `/bin/bash -p` by absolute path, finds its tools in the
  system's directories alone, and refuses one in a directory the job's user
  can write to (see Requirements). Put nothing you distrust in a job that
  signs.
- Credentials use mode-0700 directories and mode-0600 files. The action
  prefers a writable tmpfs mount at `/dev/shm`. Otherwise its work
  directory uses `RUNNER_TEMP`, or the system temporary directory if unset;
  the private GPG home falls back to `/tmp` to keep agent socket paths short.
- Cleanup attempts to overwrite secret files before removing them. The
  parent defers `SIGTERM`, `SIGINT` and `SIGHUP` during final cleanup and
  attempts each stage independently: credential-tree erasure, private Git
  home erasure, GPG-agent shutdown and GPG-home erasure, then container
  removal. One failed stage does not skip the others; incomplete cleanup
  produces an error or warning. A composite action has no post step.
- Captured runner subprocesses use kill-and-poll after cancellation or a
  timeout, without an unbounded post-kill wait. Agent shutdown and container
  removal have time budgets, but processes stuck in uninterruptible kernel
  I/O (D state) remain the runner operator's responsibility.
- **No unconditional erasure or no-disk guarantee applies.** Tmpfs can swap;
  overwriting cannot erase copies in swap, copy-on-write storage, journals,
  snapshots or crash dumps. Crashes, `SIGKILL`, runner loss and blocked I/O
  can prevent cleanup. Use isolated, disposable runners and suitable
  storage, swap and crash-dump controls.
- The signing step receives secrets in its startup environment, then hands
  them through an anonymous in-memory file and re-executes without those
  environment values before starting child tools. The client receives
  credentials as files, not secret values in arguments or its environment;
  `docker inspect` exposes mount paths, not those input values. This does
  not protect secrets from other code running as the job's user.
- `gpg` decrypts in a private home, not the runner's keyring. It requests
  symmetric passphrase caching off where supported and attempts to stop its
  private agent before erasing that home.
- The container maps to the runner's user, drops every capability and sets
  `no-new-privileges`; the workflow owns the signatures and git objects it
  produces. This does not make an untrusted client image safe.
- No Git process uses the workspace as its repository. A trusted native
  `git config --file ... --no-includes` reads `.git/config` as data from a
  private working directory; configuration includes cause rejection. Git
  and Sigul operate in a private repository with clean configuration and
  automatic GC and maintenance disabled. Real tag signing shares the
  workspace object store and records the result by writing a ref file;
  dry runs use a separate store without workspace writes. A
  server-scoped credential helper supplies the push token from a private
  file, subject to the successful-fetch lease described above.

## Requirements

- **A Linux runner with Docker**, rootful or rootless. The action refuses a
  daemon that remaps user namespaces (`userns-remap`): no container user there
  is the runner's own. Where the daemon labels containers with SELinux, the
  action runs the client with labelling waived (`label=disable`), as
  `global-jjb`'s signing job did, so that it can read the directories the
  action mounts; the container still runs as the runner's user with every
  capability dropped. The legacy client needs `linux/amd64`; the modern
  client also runs on `linux/arm64`.
- **Host Python 3.10 or later with current vendor security patches**. Use a
  vendor-supported runtime and keep its standard library and native
  dependencies patched. The version floor is not a security baseline, and
  extraction no longer depends on historical `tarfile` filter backports.
- **`python3`, `docker`, `git` and `gpg` in the system's own directories**,
  and nowhere the job's user can write: Debian's and Ubuntu's default `PATH`
  of `/usr/local/bin`, `/usr/bin`, `/bin`, their `sbin` siblings and
  `/snap/bin`. The action never runs a tool from the job's `PATH`, to which
  an earlier step could add one, and refuses a tool whose directory the
  runner's user, or anyone, can write to. GitHub-hosted Ubuntu runners leave
  `/usr/local/bin` world-writable, so the action refuses a tool planted there
  with no privilege at all, rather than run it; install tools in a directory
  that root alone can write to. These four tools, and the Docker daemon, are
  what the action trusts on the runner: the legacy action ran its own logic
  inside the client container and trusted the daemon alone, so moving the
  orchestration to the runner, which every other property here depends on,
  adds the runner's Python, gpg, git and docker CLI to what must be sound.
- **Network access to the bridge**, on port 44334:

<!-- markdownlint-disable MD013 -->

| Bridge                                       | Infrastructure | Projects                  |
| -------------------------------------------- | -------------- | ------------------------- |
| `sigul-bridge-yul.linuxfoundation.org`       | Legacy         | ONAP, OpenDaylight, EdgeX |
| `sigul-bridge-us-west-2.linuxfoundation.org` | Legacy         | O-RAN-SC, DENT            |
| `sigul-bridge.opensearch.org`                | Modern         | OpenSearch                |

<!-- markdownlint-enable MD013 -->

Restrict signing-job egress to the selected bridge, required image registries
and GitHub checkout endpoints. The live workflow uses an inline block policy
for one approved bridge and the selected registry, not the organisation's
broader allow-list. Its required `SIGUL_URI` must match the effective client
configuration, including any bundled override, and one bridge above for the
selected infrastructure.

### Production prerequisites

- Resolve the [client-image dependency work](#choosing-the-sigul-client): a
  fixed modern image must be rebuilt and published upstream, then its digest
  reviewed, updated and rescanned here. Legacy use instead requires the
  documented unsupported-client exception, owner, retirement date and
  isolated runner; that exception does not resolve dependency findings.
- Create and protect the signing environment before adding credentials.
  Configure required reviewers and allowed deployment refs outside this
  repository; an `environment:` name in YAML does not prove those controls
  exist. Trust every step, action and image in the signing job.
- Complete a non-dry live test against the intended bridge/server for each
  operation you will use, and verify the result against an independently
  trusted expected public key. A dry run or mock result cannot establish
  real signing compatibility or key authorisation.
- Gate publication on independent cryptographic verification of every
  output, using a trusted verification keyring restricted to the expected
  public key. The action checks file presence and tag structure, not OpenPGP
  authenticity. For tags, keep `push-tag: "false"` until verification and
  publish with an expected-ID lease; do not treat a successful action or
  `validation_status: passed` as permission to publish.

## Testing

The automated test workflow never contacts a bridge. It tests in three
layers:

- **Unit and regression tests** cover input rules, authenticated GPG bundles,
  bounded extraction, configuration parsing, cancellation and cleanup, and
  tag payloads and publication leases in throwaway repositories, under
  Python 3.10 and 3.12.
- **Validation** runs the action against inputs it must refuse. Assertions
  require both a failed step and `validation_status: rejected`; a later
  image-pull or credential failure is not a validation rejection.
- **End-to-end** runs once per client image and architecture, with credentials
  made by each image's own `certutil`:
  - dry runs inside the real pinned images, whose own Sigul code loads the
    configuration and opens the NSS database;
  - signing-control-flow tests inside a pinned image with a mock `sigul`
    added, served from a local registry as a bespoke image. These exercise
    retries, output ownership and tag write-back, not real-server signing
    or cryptographic verification;
  - credentials the action must refuse;
  - code planted by an earlier step: a `BASH_ENV` file, workspace Python
    modules and impostor tools on the job's `PATH`, which must not run with
    secrets, and impostors in a writable `/usr/local/bin`, which the action
    must refuse before running.

### Live signing

Run `.github/workflows/live-signing.yaml` by hand to test real infrastructure
with a throwaway file or a local tag that it never pushes. `dry-run` defaults
to `true`; `allow-legacy` defaults to `false`. Set the latter to `true` under
the approved exception for any built-in legacy run, including a dry run.

Before dispatching, create and protect `sigul-legacy` or `sigul-modern` as
described in the production prerequisites. Configure the credentials listed
in the workflow's opening comment. The checked-in workflow does not create
reviewer or ref-protection rules.

- **Set `SIGUL_URI` for this workflow** as a GitHub environment secret or
  variable, even for dry runs. It must identify one approved bridge for the
  selected infrastructure and match `bridge-hostname` in the effective
  client configuration. `SIGUL_IP` remains optional for a hosts entry.
- The inline harden-runner policy blocks egress except for that selected
  bridge on port 44334, the selected image registry's endpoints and GitHub
  checkout over HTTPS. It does not enable all bridges or unrelated
  publishing endpoints.
- **Every non-dry run requires the GitHub environment variable
  `SIGUL_PUBLIC_KEY`**: the independently trusted, armoured public signing
  key. The workflow
  supplies it to the shell as `PUBLIC_KEY`, refuses a missing key before the
  credentialed action, then imports it into a fresh GPG home and runs
  `gpg --verify` or `git verify-tag`. Dry runs do not require this variable.

A passing automated workflow is not proof that the server signs or that the
returned signature verifies. Complete the non-dry live verification before
production use, including after a client-image update.

## Layout

- `action.yaml` holds the inputs and two steps: a check, then signing.
- `scripts/` holds the Python that runs on the runner.
- `scripts/container/` runs inside the client image. It stays valid under
  Python 2.7, which the legacy image ships, as well as Python 3.
- `containers/` holds the pinned client images.

[sigul]: https://pagure.io/sigul
[legacy]: https://github.com/lfit/sigul-sign-action
[rsd]: https://github.com/lfit/releng-sigul-docker
