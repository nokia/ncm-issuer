# Testing and CI

This document describes how the pull request checks and the end to end (e2e) workflows are
organised and which Kubernetes and cert-manager versions we test against.

## Philosophy

The workflows separate two independent concerns:

* **Compatibility.** Does ncm-issuer work across the supported range of Kubernetes and
  cert-manager versions? This is covered by a single lightweight smoke scenario (issue a
  certificate, renew it, verify the chain) for both `Issuer` and `ClusterIssuer`, run across
  a reduced version matrix.
* **Feature behaviour.** Do SAN handling, key algorithms, CA name/id selection, client
  authentication behave correctly? This logic does not depend on the platform version, so
  each feature test runs once on the newest supported environment.

## When tests run

| Trigger | Workflow | Scope |
|:--|:--|:--|
| Pull request or push to `main` or a `release-*` branch | `build.yml` | lint, workflow lint, action pinning, version consistency, unit tests, binary build |
| Pull request or non-main branch | `e2e-limited.yml` | one fast smoke |
| Push to `main` | `e2e.yml` | feature tests plus a small signer smoke matrix |
| Nightly (02:00 UTC) and manual dispatch | `e2e-nightly.yml` | full compatibility diagonal plus all feature tests |
| Pull request, push to `main` or a `release-*` branch, and weekly | `codeql.yml` | CodeQL security and quality queries for Go |
| Pull request, push to `main` or a `release-*` branch, and weekly | `security.yml` | reachable Go vulnerabilities, container image scan |
| Push to `main`, a branch protection change, and weekly | `scorecard.yml` | OpenSSF Scorecard supply chain rating |

## Compatibility matrix

We do not test the full cartesian product of versions. Each cert-manager release supports
only a roughly four version Kubernetes band, so most cartesian cells are combinations that
upstream never supports. Instead we test along the supported diagonal, hitting the low and
high Kubernetes boundary of each cert-manager release we care about.

| cert-manager | Kubernetes (low / high) | Notes |
|:--|:--|:--|
| 1.21 | 1.36 | newest of both, canary |
| 1.20 | 1.32 / 1.35 | latest stable |
| 1.19 | 1.31 / 1.35 | previous supported line |
| 1.18 | 1.29 / 1.33 | recently retired, still widely deployed |

Cells marked experimental in the matrix use `continue-on-error` so that an unreleased
version or a microk8s channel that has been removed for an end of life Kubernetes release
does not block the nightly run.

## Bumping versions

* The compatibility diagonal lives in the `setup-matrix` job of
  `.github/workflows/signer-tests.yml`. Edit the smoke and full `include` lists there.
* The feature test environment defaults live in the `k8s-version` and `certmgr-version`
  inputs of each feature workflow (`clientauth-test.yml`, `san-test.yml`, `pkey-tests.yml`,
  `caname-id-test.yml`). Override them from the orchestrators when needed.

## Shared setup

Common steps (provision microk8s, install cert-manager and tooling, load the image, collect
diagnostics on failure) are factored into composite actions under `.github/actions/` so the
individual workflows stay small and consistent.

## Security scanning

Four scans run on their own schedules as well as on changes, because a dependency or a base image
package can become vulnerable without anything in the repository changing.

| Scan | Covers | Fails the job when |
|:--|:--|:--|
| `make vuln` (govulncheck) | Go dependencies | a vulnerability is reachable from this module's code |
| Trivy | the built container image, including Alpine packages | a fixable `HIGH` or `CRITICAL` is present |
| CodeQL | the Go source | a security or quality query matches |
| Scorecard | repository and release configuration | never, it only reports a rating |

`make vuln` is the one to run locally. It reports only vulnerabilities on a call path the binary
can actually reach, so a finding is usually worth acting on rather than suppressing. Fix it by
bumping the module that carries it, then rerun. Vulnerabilities in modules that are required but
not called are listed for information and do not fail the build.

Trivy is run twice in the same job: once to produce the full SARIF result set for the Security tab,
then once more restricted to fixable high severity findings, which is the run that can fail the
job. `ignore-unfixed` is set, so a vulnerability with no upstream fix is reported but does not
block a pull request.

Results are published to code scanning, and Trivy and CodeQL findings appear under
[Security](https://github.com/nokia/ncm-issuer/security). A pull request from a fork runs with a
read-only token and cannot write security events, so for those the findings are visible in the job
log only and the Security tab is fed by the branch and scheduled runs instead.

Every release also gets an SPDX SBOM of the published image, generated from
`ghcr.io/nokia/ncm-issuer:<tag>` and attached to the GitHub release by the `sbom` job in
`release.yml`.

## Adding a third-party action

Third-party actions must be referenced by full commit SHA with the version in a trailing
comment, because a tag like `@v7` can be repointed at any commit. `make lint-actions-pinned`
enforces this and runs in the `build.yml` lint job. After adding an action by tag, run:

```bash
make pinact
PINACT_GITHUB_TOKEN=<token> ./bin/pinact run
```

That rewrites the reference to the SHA the tag currently points at and appends the version
comment. Dependabot then keeps both the SHA and the comment up to date. References to local
actions and reusable workflows under `./.github/` stay as paths and are not pinned.

## Base images

Base images carry both a version tag and a digest, as in `alpine:3.24.1@sha256:...`. Docker
resolves the digest and treats the tag as documentation, so the build is reproducible even though
the upstream tag keeps moving. Dependabot watches both Dockerfiles and updates the tag and the
digest together.

Pin the digest of the multi-architecture index, not of one architecture's manifest, or the
`linux/arm64` release build will fail to find a matching image. Requesting the manifest with an
index media type returns the right one:

```bash
docker buildx imagetools inspect alpine:3.24.1
```

The controller image also runs `apk --no-cache upgrade` on top of its pinned base. Alpine publishes
package fixes faster than it rebuilds its images, so even a current digest can contain OS packages
that already have a fix waiting in the repository, which the image scan then reports as fixable. The
upgrade clears those, at the cost of resolving the package set at build time rather than fixing it
by the digest alone.

The `golang` builder image is held on the 1.26 line by an `ignore` entry in
`.github/dependabot.yml`, so only 1.26 patch releases are proposed. The build toolchain has to stay
in step with the `go` directive in `go.mod`, which is what the workflows read, and with the Go
version the pinned golangci-lint was built against, since a linter built for an older Go cannot
read export data written by a newer one. Moving to a newer Go line is therefore a deliberate change
to `go.mod`, the Dockerfile and that bound together, and it has to happen before the 1.26 line
stops receiving upstream security fixes, which is when the second Go release after it ships.

## Version numbers

The release version is written in several files, and `main.go` is the one that counts: both the
Makefile and `release.yml` read `chartVersion` and `imageVersion` from it to tag images and name
release tarballs. Everything else has to agree with it.

| File | Holds | Expected to be |
|:--|:--|:--|
| `main.go` | `chartVersion`, `imageVersion` | the source |
| `helm/Chart.yaml` | `appVersion` | `imageVersion` |
| `helm/Chart.yaml` | `version` | `chartVersion` plus a `-chart` suffix |
| `helm/values.yaml` | both image `tag` keys | `imageVersion` |
| `ncm-issuer-utils/ncm-issuer-utils.yaml` | the sidecar image tag | `imageVersion` |
| `RELEASE_NOTES.md` | the topmost `## Version` heading | `chartVersion` and `imageVersion` |

To bump a release, rewrite the code and the chart in one step, then write the release notes section
by hand, since a new release adds a section rather than renaming the previous one:

```bash
make set-version VERSION=1.2.4
```

`make check-version` reports anything out of step and the `versions` job in `build.yml` runs it on
every pull request, so a half-finished bump fails the build instead of shipping a chart that
references an image tag that was never published.

## Third-party notices

`THIRD_PARTY_NOTICES.md` lists every direct dependency with its pinned version and licence, which
goes stale as soon as a dependency bump lands. `make check-notices` compares it against `go.mod`,
and the same `versions` job runs it on every pull request.

A direct dependency is a `require` without an `// indirect` marker, and each one needs exactly one
table row whose link text is the module path, whose second column is the version from `go.mod` and
whose third column names a licence. The check fails on a module that is undocumented, one still
documented after it left `go.mod`, a version that no longer matches and a row with no licence.

Which table a module belongs in is derived rather than trusted: a module imported by any file other
than a `_test.go` is linked into the released binary and belongs under the runtime heading, and
everything else is test-only. That reads tracked Go files with `git grep`, so the check needs no Go
toolchain and downloads no modules.

Nothing is rewritten, since the `Use` column is written by hand. Take the licence for a new
dependency from the module's own `LICENSE` file, which `make vendor` writes into `vendor/`.

## Checkout credentials and token permissions

Every workflow declares a top-level `permissions` block and any job needing more than
repository read access declares that itself. `release.yml` and `update-docs.yml` start from
`permissions: {}` because their jobs each need a different scope.

Checkout steps set `persist-credentials: false`, so the workflow token is not left in the
workspace for later steps to read. Three checkouts set it to `true` instead and say why in a
comment: both checkouts in the `pages` job of `release.yml` and the `gh-pages` checkout in
`update-docs.yml`. The `git-auto-commit-action` steps that follow them push using exactly those
credentials, so removing the setting from any of the three breaks publishing.
