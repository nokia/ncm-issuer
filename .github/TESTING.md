# Testing and CI

This document describes how the end to end (e2e) workflows are organised and which
Kubernetes and cert-manager versions we test against.

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
| Pull request or non-main branch | `e2e-limited.yml` | one fast smoke |
| Push to `main` | `e2e.yml` | feature tests plus a small signer smoke matrix |
| Nightly (02:00 UTC) and manual dispatch | `e2e-nightly.yml` | full compatibility diagonal plus all feature tests |

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
