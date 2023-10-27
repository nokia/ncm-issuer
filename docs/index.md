---
hide:
  - navigation
title: Home
---

# ncm-issuer

[![build](https://github.com/nokia/ncm-issuer/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/nokia/ncm-issuer/actions/workflows/build.yml)
[![e2e](https://github.com/nokia/ncm-issuer/actions/workflows/e2e.yml/badge.svg?branch=main)](https://github.com/nokia/ncm-issuer/actions/workflows/e2e.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/nokia/ncm-issuer)](https://goreportcard.com/report/github.com/nokia/ncm-issuer)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=coverage)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)

<p align="center">
   <img src="./assets/ncm-issuer-gopher.png" alt="ncm-issuer-gopher" width="40%"/>
</p>

## What is ncm-issuer?

ncm-issuer is a [Kubernetes](https://kubernetes.io) controller (external [cert-manager](https://cert-manager.io/) issuer) that allows to integrate with
[Nokia NetGuard Certificate Manager (NCM)](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/)
PKI system to sign certificate requests. The integration with NCM makes it easy to obtain non-selfsigned certificates for
applications and to ensure that they are valid and up to date.

## How to get started?

Simply click the documentation tab in the navigation panel. All the steps required to install the ncm-issuer are
described there, along with a tutorial on how to issue your first certificate. If you feel that something is missing 
in the documentation, please report it to one of the maintainers, and it will definitely be added soon!

## Maintainers

> [:material-email-arrow-right:](mailto:dawid.machoczek@nokia.com)
> Dawid Machoczek ([@raczu](https://github.com/raczu/))

> [:material-email-arrow-right:](mailto:adam.korba@nokia.com)
> Adam Korba ([@BbqGamer](https://github.com/BbqGamer/))


## License

This project is licensed under the terms of **Apache 2.0 License** and available on
[GitHub](https://github.com/nokia/ncm-issuer).

