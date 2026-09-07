<!-- markdownlint-disable MD013 -->
# Contributing to ncm-issuer

Thanks for your interest in ncm-issuer. This guide covers how to propose a change and get it merged.

## Before you start

* Questions and help requests belong in [SUPPORT.md](SUPPORT.md).
* Security vulnerabilities must follow [SECURITY.md](SECURITY.md). Do not open a public issue, pull request or discussion for them.
* If your change adds a feature, alters the `Issuer` or `ClusterIssuer` API or changes default behaviour, open an issue first so the approach can be agreed before you write code.

## Development environment

You need:

* Go, at the version declared in [`go.mod`](go.mod)
* `make`
* Docker with [buildx](https://docs.docker.com/build/) to build images
* `kubectl` and a throwaway cluster such as [kind](https://kind.sigs.k8s.io) for manual checks

`controller-gen`, `golangci-lint`, `actionlint`, `pinact`, `kustomize` and `envtest` are installed into `./bin` by the Makefile at pinned versions, so you do not install them yourself. Bumping a pinned version in the Makefile is enough to make the next run reinstall it.

`vendor/` is not tracked. Run `make vendor` after you change dependencies.

## Everyday commands

| Command | What it does |
| --- | --- |
| `make build` | Build the manager binary |
| `make test` | Run the unit tests against envtest |
| `make lint` | Run golangci-lint |
| `make lint-fix` | Run golangci-lint and apply the fixes it can make |
| `make lint-config` | Validate `.golangci.yml` against the linter's own schema |
| `make lint-actions` | Lint the workflows with actionlint |
| `make lint-actions-pinned` | Check that every action is pinned to a commit SHA |
| `make vuln` | Report known vulnerabilities reachable from this module |
| `make docker-build` | Build the container image |
| `make help` | List every target |

Run `make lint` and `make test` before pushing. CI runs the same targets, so this saves a round trip.

## Generated files

CRDs and deepcopy methods are generated from the types in `api/`. After changing anything there, regenerate and commit the result:

```bash
make manifests generate
```

Do not hand-edit `config/crd/bases/` or any `zz_generated.*.go`.

## Coding conventions

* Keep the tree `gofmt` clean. `make build` runs `go fmt` and `go vet`.
* Treat `.golangci.yml` as authoritative. Fix findings instead of widening the exclusion list.
* Give every `nolint` a specific linter and a reason, such as `//nolint:gosec // the path is validated above`.

## Changing workflows

Third-party actions must be pinned to a full commit SHA with the version in a trailing comment, and `make lint-actions-pinned` fails the build otherwise. [`.github/TESTING.md`](.github/TESTING.md) explains how to add an action and describes the conventions for checkout credentials and workflow token permissions.

## Tests

`make test` covers the unit tests. On top of that, CI runs two end to end suites against a live cluster:

* the limited suite on every pull request,
* the full suite on `main` and on demand.

Neither needs credentials, so both run on pull requests from forks. [`.github/TESTING.md`](.github/TESTING.md) documents the suites and the compatibility matrix.

## Dependency and image scanning

CodeQL, govulncheck and a Trivy image scan run on every pull request. If a dependency bump is what fixes a finding, include it in your pull request. Run `make vuln` locally to see what govulncheck reports, and see [Security scanning](.github/TESTING.md#security-scanning) for what each scan covers and what makes it fail.

## Documentation

User-facing documentation lives in `README.md` and `docs/`, and is published to <https://nokia.github.io/ncm-issuer/> from `main`. Update it in the same pull request as the change it describes. To preview the site:

```bash
pip install mkdocs-material mkdocs-awesome-pages-plugin
mkdocs serve
```

Add an entry to `RELEASE_NOTES.md` for anything a user can observe.

## Commits

The repository uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) with a scope:

```text
feat(controller): retry enrollment when NCM returns a pending CSR
fix(helm): correct the service account annotation key
docs(readme): describe the outbound proxy settings
ci(actions): pin third-party actions to commit SHAs
```

Keep separate concerns in separate commits. Implementation, tests and documentation are easier to review and revert apart.

## Pull requests

1. Work on a branch in your fork.
2. Complete the pull request template, including how you verified the change.
3. Keep the pull request focused. A refactor bundled with a fix is hard to review.
4. Merging needs one approving review and passing checks.
5. Bring your branch up to date with `main` if it falls behind.

A maintainer may push follow-up commits to your branch or ask you to split a pull request that covers several changes.

## Licence

ncm-issuer is licensed under [Apache 2.0](LICENSE). By contributing you agree that your contribution is provided under that licence.
