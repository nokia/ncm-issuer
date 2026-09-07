# Security policy

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues, pull requests or discussions.

Use either of these channels:

* **GitHub private vulnerability reporting** (preferred for this repository). Open the
  [Security tab](https://github.com/nokia/ncm-issuer/security/advisories) and choose *Report a vulnerability*. The report stays
  private until an advisory is published.
* **Nokia PSIRT** at `security-alert@nokia.com`, which is the entry point of Nokia's
  [Coordinated Vulnerability Disclosure programme](https://www.nokia.com/we-are-nokia/security/products/cvd/). Reports can be
  encrypted with the [Nokia public key](https://www.nokia.com/.well-known/nokia-public-key.asc). Anonymous submissions are accepted.

If you are a Nokia customer, you can also raise the issue through your usual Nokia support or account contact.

## What to include

The more of this you can provide, the faster we can triage:

* the ncm-issuer version (chart and image) plus the cert-manager and Kubernetes versions,
* the commit you tested against,
* steps to reproduce, including a proof of concept if you have one,
* the behaviour you observed and the behaviour you expected,
* the impact you think it has, with a CVSS vector if you can provide one.

## What to expect

* We acknowledge new reports and keep you updated while we investigate.
* We agree the severity and a remediation timeline with you, based on impact and complexity.
* Fixes ship in a normal release. The release notes describe the issue once a fix is available.
* Tell us how you would like to be credited, or say if you would rather stay anonymous.

Please keep the report confidential until a fix is released.

## Supported versions

Fixes are made on the latest release line only. Upgrade to the most recent
[release](https://github.com/nokia/ncm-issuer/releases) before reporting, so the issue can be confirmed against current code.

| Version | Supported |
| ------- | --------- |
| 1.2.x   | Yes       |
| < 1.2   | No        |
