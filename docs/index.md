---
hide:
  - navigation
title: Home
---

# ncm-issuer

[![GitHub Release](https://img.shields.io/github/v/release/nokia/ncm-issuer?style=flat-square&color=blue)](https://github.com/nokia/ncm-issuer/releases)
[![GitHub Stars](https://img.shields.io/github/stars/nokia/ncm-issuer?style=flat-square&color=magenta)](https://github.com/nokia/ncm-issuer)
[![Last Commit](https://img.shields.io/github/last-commit/nokia/ncm-issuer?style=flat-square&color=green)](https://github.com/nokia/ncm-issuer/commits/main)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen?style=flat-square)](https://github.com/nokia/ncm-issuer)
[![build](https://github.com/nokia/ncm-issuer/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/nokia/ncm-issuer/actions/workflows/build.yml)
[![e2e](https://github.com/nokia/ncm-issuer/actions/workflows/e2e.yml/badge.svg?branch=main)](https://github.com/nokia/ncm-issuer/actions/workflows/e2e.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fnokia%2Fncm-issuer&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/nokia/ncm-issuer)

<p align="center">
   <img src="./assets/ncm-issuer-gopher.png" alt="ncm-issuer-gopher" width="25%"/>
</p>

## What is ncm-issuer?

ncm-issuer is a [Kubernetes](https://kubernetes.io) controller (external [cert-manager](https://cert-manager.io/) issuer) that allows to integrate with
[Nokia NetGuard Certificate Manager (NCM)](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/)
PKI system to sign certificate requests.

The integration with NCM makes it easy to obtain non-self-signed certificates for applications and to ensure that they are valid and up-to-date.

## How to get started?

Simply click the documentation tab in the navigation panel. All the steps required to install the ncm-issuer are
described there, along with a tutorial on how to issue your first certificate. If you feel that something is missing
in the documentation, please report it to one of the maintainers, and it will definitely be added soon!

## Maintainers

> [:material-email-arrow-right:](mailto:misiektoja-github@rm-rf.ninja)
> Michal Szymanski ([@misiektoja](https://github.com/misiektoja/))


## License

This project is licensed under the terms of **Apache 2.0 License** and available on
[GitHub](https://github.com/nokia/ncm-issuer).

