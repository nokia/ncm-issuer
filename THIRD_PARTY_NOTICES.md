# Third-party notices

ncm-issuer's own code is Apache-2.0, as recorded in [`LICENSE`](LICENSE). The controller links
separately licensed Go modules and its container images are built on separately licensed base
images. Versions below are the ones pinned in `go.mod`.

## Direct runtime dependencies

| Component | Pinned version | License | Use |
| --- | --- | --- | --- |
| [github.com/cert-manager/cert-manager](https://github.com/cert-manager/cert-manager) | v1.20.3 | Apache-2.0 | `CertificateRequest` and issuer API types, plus the helpers that set request conditions |
| [sigs.k8s.io/controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) | v0.24.1 | Apache-2.0 | Manager and reconciler machinery, Kubernetes client, event predicates, health probes and the metrics registry |
| [k8s.io/api](https://github.com/kubernetes/api) | v0.36.2 | Apache-2.0 | Core API types, including the `Secret` that holds NCM credentials and TLS material |
| [k8s.io/apimachinery](https://github.com/kubernetes/apimachinery) | v0.36.2 | Apache-2.0 | Object metadata, scheme and runtime types, and API error classification |
| [k8s.io/client-go](https://github.com/kubernetes/client-go) | v0.36.2 | Apache-2.0 | Client scheme registration and the event recorder |
| [k8s.io/utils](https://github.com/kubernetes/utils) | v0.0.0-20260626114624-be93311217bd | Apache-2.0 | Clock abstraction, so retry and renewal timing can be driven in tests |
| [github.com/go-logr/logr](https://github.com/go-logr/logr) | v1.4.3 | Apache-2.0 | Logging interface used throughout the controller |
| [github.com/prometheus/client_golang](https://github.com/prometheus/client_golang) | v1.23.2 | Apache-2.0 | Counter types for the enrollment and renewal metrics registered on the controller-runtime registry |

## Test-only dependencies

These are imported by the unit tests and are not linked into the released binary.

| Component | Pinned version | License | Use |
| --- | --- | --- | --- |
| [github.com/stretchr/testify](https://github.com/stretchr/testify) | v1.11.1 | MIT | Assertions and mocks in the unit tests |
| [github.com/google/go-cmp](https://github.com/google/go-cmp) | v0.7.0 | BSD-3-Clause | Value comparison in the unit tests |

## Container base images

The controller image is built on [Alpine Linux](https://alpinelinux.org/) and the troubleshooting
sidecar on [Rocky Linux](https://rockylinux.org/). Both carry their own package licenses, which are
recorded inside the images rather than here. Each release ships an SPDX SBOM of the published
controller image that enumerates its contents.

## Completeness

The tables above cover the modules this project imports directly. The full module graph, including
indirect dependencies, is recorded in `go.mod` and `go.sum`, and `make vendor` writes each module's
own license text into `vendor/`. None of these documents replace the license texts distributed by
the dependency authors.
