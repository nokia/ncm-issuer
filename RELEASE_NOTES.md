# Release Notes

## Version 1.1.9 (Chart: 1.1.9, Image: 1.1.9) - 19 Jan 2026
- **Corrected URL handling for backup API requests** (fixes #60)
- Added support for **Kubernetes** `1.35` (supported versions: `1.25 - 1.35`)
- Updated `go.mod` dependencies: **Kubernetes API** to `0.35`, **controller-runtime** to `0.22.4`, **cert-manager** to `1.19.2`
- Upgraded **Go** version used for building the binary and Docker image from `1.25.4` to `1.25.6`

## Version 1.1.8 (Chart: 1.1.8, Image: 1.1.8) - 24 Nov 2025
- **Fixed private key rotation policy handling** to align with cert-manager `>=1.18.0` changes. From this release onwards, omitting `.spec.privateKey.rotationPolicy` means **re-enrollment** (private key rotation) instead of renewal. This aligns ncm-issuer behaviour with cert-manager `v1.18.0+`, where the default rotation policy changed from `Never` to `Always`. If you require a true renew-with-same-key flow, set `.spec.privateKey.rotationPolicy` to `Never` explicitly
- Enhanced logging for certificate operations with improved certificate extraction utilities. Logs now include detailed certificate information such as **subject DN**, **serial number**, **validity period** (`notBefore`/`notAfter`), **SAN entries** (DNS names and IP addresses), **key type and size**, **signature algorithm**, **issuer details**, **operation type**, **issue duration** etc.
- Added support for **Kubernetes** `1.34` (supported versions: `1.24 - 1.34`)
- Improved resource management by ensuring proper cleanup of temporary files and HTTP response bodies to prevent resource leaks
- Added nil checks and improved error handling in **NCM API** operations
- Refactored code for improved clarity, including leader election configuration and type improvements
- Updated `ncm-issuer-utils` troubleshooting container to `1.1.8`
- Updated `go.mod` dependencies: **Kubernetes API** to `0.34`, **controller-runtime** to `0.22`, **cert-manager** to `1.19.1`
- Upgraded **Go** version used for building the binary and Docker image from `1.24.4` to `1.25.4`

## Version 1.1.7 (Chart: 1.1.7, Image: 1.1.7) - 18 Jun 2025
- Separated chart version from image tag to avoid **Harbor OCI** overwrite
- Fixed `Makefile` to save both remote and local tags in Docker archive, improving compatibility with various **Kubernetes orchestrators**
- Fully qualify golang base image as `docker.io/golang` to avoid short-name resolution error in some dev envs
- Updated `go.mod` dependencies to bump **cert-manager** to `1.18.1`

## Version 1.1.6 (Chart: 1.1.6, Image: 1.1.6) - 06 Jun 2025
- Switched to **Docker Buildx** for reliable cross-platform image builds
- Switched from **Scratch** to **Alpine** image to play more nicely with different **Kubernetes orchestrators** (and to finally have a shell!)
- Added explicit command to start `ncm-issuer` binary in Helm's `deployment.yaml` to ensure consistent container startup across **Kubernetes** environments
- Updated `ncm-issuer-utils` troubleshooting container to `1.1.6` - it is still hanging around even though the regular one has a shell now, mainly due to better security posture and clear separation
- Added new troubleshooting tools to `ncm-issuer-utils`: `procps-ng`, `lsof`, `vim-minimal`, `less`, `strace`
- Stripped symbol and **DWARF** debug info to reduce Docker image binary size
- Upgraded **Go** version used for building the binary and Docker image from `1.24.3` to `1.24.4`

## Version 1.1.5 (Chart: 1.1.5, Image: 1.1.5) - 26 May 2025
- Implemented optional **RBAC** workaround which might be needed when cert-manager is installed via the **OLM/operator** (see `certManagerRbac.operatorWorkaround.enable` in `values.yaml`)
- Added support for **Kubernetes** `1.33` (supported versions: `1.24 - 1.33`)
- Upgraded **Go** version used for building the binary and Docker image from `1.24.2` to `1.24.3`
- Updated `go.mod` dependencies (**Kubernetes API** to `0.33`, **controller-runtime** to `0.21`, **cert-manager** to `1.17.2`)

## Version 1.1.4 (Chart: 1.1.4, Image: 1.1.4) - 23 Apr 2025
- Optimizations to resolve potential startup issues under various **Kubernetes orchestrators**
- Fixed container startup error under **NCS** `24.11`
- Upgraded **Go** version used for building the binary and Docker image from `1.22.10` to `1.24.2`
- Updated `go.mod` dependencies (**Kubernetes API** to `0.32`, **controller-runtime** to `0.20.4`, **cert-manager** to `1.17.1`)
- Corrected **cert-manager** import paths throughout the codebase
- Resolved **Fatalf** non-constant format string warnings
- Switched to the new metrics server setup via the **Metrics** field
- Updated **golangci-lint** to `v1.64.8`
- Fixed `Makefile` quoting issues to support paths with spaces
- Improved error handling across **Go** code
- Enabled status subresource in the fake client for unit tests

## Version 1.1.3 (Chart: 1.1.3, Image: 1.1.3) - 22 Mar 2025
- Changed the list of supported **Kubernetes** versions to `1.24 - 1.32`

## Version 1.1.2 (Chart: 1.1.2, Image: 1.1.2) - 13 Jan 2025
- Support for setting `notBefore` and `notAfter` parameters in **NCM** certificate requests corresponding to suggested **Duration** parameter in `cert-manager.io/v1` **Certificate** object kind. `notBefore` is set to the current time when cert is being enrolled. Feature is available for **NCM** `>= 24.11`, in older release new parameters are ignored
- Added issuer `.spec.caID`/`CASHREF` validation, so there is an error presented if the user specifies wrongly formatted value
- Bumped **Go** version to `1.22.10`

## Version 1.1.1 (Chart: 1.1.1, Image: 1.1.1) - 01 Mar 2024
- Changed the list of supported **Kubernetes** version to `1.24 - 1.29`

## Version 1.1.0 (Chart: 1.1.0, Image: 1.1.0) - 27 Oct 2023
- The **Issuer** and **ClusterIssuer** definitions are improved to use more user-friendly names and grouped into appropriate sections
- Improved **NCM API** selection mechanism
- Improved handling **CSR** statuses returned by **NCM**
- **Helm** chart is rewritten according to the rules given in the Helm documentation
- Added option to set **HTTP client timeout**
- Added option to set a time indicating how often **NCM API(s)** availability should be checked (related to new **NCM API** selection mechanism)
- Added **Prometheus** support to allow monitoring of the total number of enrollment or renewal operations. Each of these operations also has metrics responsible for determining how many of them were successful or failed. The metrics attempt to reflect the number of **CSRs** or renewals sent to the **NCM**, if request is rejected or postponed by **NCM**, this state will be reflected as failure of the enrollment operation, while accepting and returning appropriate resource will result in successful enrollment or renewal operation (use the prefix `"ncm_issuer"` in **Prometheus** query to see all possible metrics)
- Added possibility to configure verbosity of logging
- Added **sidecar** for debugging purposes
- Fixed occasionally encountered data-races when accessing saved **Issuer** or **ClusterIssuer** config

## Version 1.0.3 (Chart: 1.0.3, Image: 1.0.3) - 11 Mar 2023
- Added possibility to specify secondary **NCM EXTERNAL API** server in case of lack of connection to the main one, server is specified as a parameter `"ncmSERVER2"` in issuer or cluster issuer yaml file
- Fixed misinterpretation in case of manually triggering rotation of a private key
- Fixed bug related to getting certificate object when the certificate name is long
- Added possibility to include certificate chain in `ca.crt` by setting `"chainInSigner"` in issuer or cluster issuer yaml file to `"true"`
- Added possibility to include only end-entity certificate in `tls.crt` by setting `"onlyEECert"` in issuer or cluster issuer yaml file to `"true"`
- Bumped **Go** from `1.17` to `1.19.6`
- Fixed bugs during certificate renewal
- Fixed misinterpretation when **PK rotation policy** is set to `"Always"`

## Version 1.0.2 (Chart: 1.0.2, Image: 1.0.1) - 16 May 2022
- Update **Go** version to `1.17`

## Version 1.0.1 (Chart: 1.0.1, Image: 1.0.0) - 11 Apr 2022
- Added **NCM Issuer** version to logging

## Version 1.0.0 (Chart: 1.0.0, Image: 0.1.149) - 04 Apr 2022
- Changed name of project
- Added support for private key rotation policy set to `"always"`
- Changed **CRD** version to `v1`
- Upgrade **Go** version to `1.16.15`
- Added **CSR** approve check
- Support for **cert-manager** using **API v1**

## Version 0.6.9 (Chart: 0.6.9, Image: 0.1.141) - 08 Mar 2022
- Renewal process will not be started without certificate details

## Version 0.6.8 (Chart: 0.6.8, Image: 0.1.140) - 07 Mar 2022
- Changed secret name generation method
- Added `release_notes.txt` file
- Fixed bug connected to illegal characters in secret names
