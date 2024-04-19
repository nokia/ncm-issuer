<!-- markdownlint-disable  MD013 MD014 MD033 -->
# ncm-issuer

<div id="top"></div>

[![build](https://github.com/nokia/ncm-issuer/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/nokia/ncm-issuer/actions/workflows/build.yml)
[![e2e](https://github.com/nokia/ncm-issuer/actions/workflows/e2e.yml/badge.svg?branch=main)](https://github.com/nokia/ncm-issuer/actions/workflows/e2e.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/nokia/ncm-issuer)](https://goreportcard.com/report/github.com/nokia/ncm-issuer)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=coverage)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)

<p align="center">
   <img src="./assets/ncm-issuer-logo.png" alt="ncm-issuer-logo" width="35%"/>
</p>

ncm-issuer is a [Kubernetes](https://kubernetes.io) controller (external [cert-manager](https://cert-manager.io/) issuer) that allows to integrate with
[Nokia NetGuard Certificate Manager (NCM)](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/)
PKI system to sign certificate requests. The integration with NCM makes it easy to obtain non-selfsigned certificates for
applications and to ensure that they are valid and up to date.

## Table of contents

* [Prerequisites](#prerequisites)
* [Installation and configuration](#installation-and-configuration)
  * [Installing using Helm](#installing-using-helm)
    * [Using own (local or remote) registry](#using-own--local-or-remote--registry)
    * [Configuration](#configuration)
      * [NCM REST API credentials](#ncm-api-credentials)
      * [TLS without client authentication](#tls-without-client-authentication)
      * [TLS with client authentication](#tls-with-client-authentication)
* [Custom resource definitions (CRDs)](#custom-resource-definitions--crds-)
  * [Issuer resource](#issuer-resource)
  * [ClusterIssuer resource](#clusterissuer-resource)
  * [Issuer and ClusterIssuer fields overview](#issuer-and-clusterissuer-fields-overview)
* [Usage](#usage)
  * [Create an Issuer](#create-an-issuer)
  * [Signing certificate](#signing-certificate)
  * [Renewing or reenrolling certificate](#renewing-or-reenrolling-certificate)
* [Troubleshooting](#troubleshooting)

## Prerequisites

Prerequisites for building and using ncm-issuer:

* [NCM](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) release 21 or later,
* [Kubernetes](https://kubernetes.io) version 1.24 - 1.29,
* [cert-manager](https://cert-manager.io/) version 1.0.0 or later,
* [Docker](https://docs.docker.com/engine/install/) version 20.10.0 or later,
* [Helm](https://helm.sh/docs/intro/install/) v3.

**:warning: Warning:** Install docker-ce instead of default if you are using CentOS, RedHat or Fedora!

### Installing using Helm

The easiest way to install ncm-issuer in Kubernetes cluster is to use Helm. The image will be automatically downloaded from public repository.

<img src="./assets/installation.gif" alt="installation"/>

Install ncm-issuer using the command:

  ```bash
  $ helm install \
  ncm-issuer \
  --create-namespace --namespace ncm-issuer \
  helm
  ```

On the other hand, if you did not use `git`, but downloaded the packaged version of ncm-issuer use:

  ```bash
  $ helm install \
  ncm-issuer \
  --create-namespace --namespace ncm-issuer \
  ncm-issuer/charts/ncm-issuer
  ```

#### Using own (local or remote) registry

In case you want to use your own registry, just change the value pointing to a specific registry
in the `values.yaml` file in directory that contains Helm files. Then just repeat the steps
mentioned above.

  ```bash
  sed -i "s|docker.io/misiektoja|<your-registry>|g" values.yaml
  ```

**:warning: Warning:** Using this command will also change the registry pointing to the image location of troubleshooting sidecar.
Bear this in mind if you want to use sidecar as well.

However, if you do not know where to get image from, because you cloned the repository
just use the command:

  ```bash
  $ make docker-build
  ```

or (if you also want to save image)

  ```bash
  $ make docker-save
  ```

Saved image should appear in the path `./builds/ncm-issuer-images/`.

### Configuration

To make the ncm-issuer work properly, it is necessary to create few Kubernetes secrets
that contains credentials to NCM REST API and TLS configuration.

<img src="./assets/configuration.gif" alt="configuration" />

#### NCM REST API credentials

  ```bash
  $ kubectl create secret generic \
  <secret-name> \
  -n <namespace> \
  --from-literal=username=<username> \
  --from-literal=usrPassword=<password>
  ```

#### TLS without client authentication

  ```bash
  $ kubectl create secret generic \
  <secret-name> \
  -n <namespace> \
  --from-file=cacert=<ca-for-tls.pem>
  ```

#### TLS with client authentication

  ```bash
  $ kubectl create secret generic \
  <secret-name> \
  -n <namespace> \
  --from-file=cacert=<ca-for-tls.pem> \
  --from-file=key=<client-auth-pkey.pem> \
  --from-file=cert=<client-auth-cert.pem>
  ```

To make sure that specific secret have been created correctly, you can check this
by using command:

  ```bash
  $ kubectl -n <namespace> describe secrets <secret-name>
  ```

## Custom resource definitions (CRDs)

### Issuer resource

Below is an example `yaml` file containing `Issuer` definition:

  ```yaml
  apiVersion: certmanager.ncm.nokia.com/v1
  kind: Issuer
  metadata:
    name: example-ncm-issuer
    namespace: ncm-ns
  spec:
    # caName or caID is always required.
    caName: ncm-ca
    caID: e1DefAscx
    provisioner:
      # mainAPI is always required.
      mainAPI: https://nokia-ncm.local
      backupAPI: https://nokia-backup-ncm.local
      httpClientTimeout: 10s
      healthCheckerInterval: 1m
      # authRef is always required.
      authRef:
        name: ncm-rest-auth
        namespace: ncm-ns
      tlsRef:
        name: ncm-tls
        namespace: ncm-ns
    profileId: "101"
    useProfileIDForRenew: true
    reenrollmentOnRenew: true
    noRoot: true
    chainInSigner: false
    onlyEECert: true
  ```

**:warning: Warning:** With release `1.1.0-1.1.0` the name of some fields in `Issuer` has changed, but old names are
still supported and can be used (this applies to: `CASNAME`, `CASHREF`, `ncmSERVER`, `ncmSERVER2`, `secretName`,
`tlsSecretName`, `authNameSpace`).

### ClusterIssuer resource

With the `ClusterIssuer`, the definition does not differ from that presented
with `Issuer`, and the only differences are in the field `kind` and the non-existence of field
`.metadata.namespace` due to `Cluster` scope reasons.

  ```yaml
  apiVersion: certmanager.ncm.nokia.com/v1
  kind: ClusterIssuer
  metadata:
    name: example-ncm-clusterissuer
  spec:
    ...
  ```

### Issuer and ClusterIssuer fields overview

| Field                                     | Description                                                                                                                                                                                                                                                                     | Supported from |
|:------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------:|
| `.spec.caName`                            | Name of an existing CA in the NCM, which will be used to issue certificates (required if `.spec.caID` is not specified)                                                                                                                                                         |  1.1.0-1.1.0   |
| `.spec.caID`                              | Unique HREF identifier for existing CA in the NCM, which will be used to issue certificates (required if `.spec.caName` is not specified)                                                                                                                                       |  1.1.0-1.1.0   |
| `.spec.provisioner.mainAPI`               | The URL to the main NCM REST API (always required)                                                                                                                                                                                                                              |  1.1.0-1.1.0   |
| `.spec.provisioner.backupAPI`             | The URL to the backup NCM REST API in case of the lack of connection to the main one                                                                                                                                                                                            |  1.1.0-1.1.0   |
| `.spec.provisioner.httpClientTimeout`     | Maximum amount of time that the HTTP client will wait for a response from NCM REST API before aborting the request                                                                                                                                                              |  1.1.0-1.1.0   |
| `.spec.provisioner.healthCheckerInterval` | The time interval between each NCM REST API health check                                                                                                                                                                                                                        |  1.1.0-1.1.0   |
| `.spec.provisioner.authRef`               | Reference to a Secret containing the credentials (user and password) needed for making requests to NCM REST API (always required)                                                                                                                                               |  1.1.0-1.1.0   |
| `.spec.provisioner.tlsRef`                | Reference to a Secret containing CA bundle used to verify connections to the NCM REST API. If the secret reference is not specified and selected protocol is HTTPS, InsecureSkipVerify will be used. Otherwise, TLS or mTLS connection will be used, depending on provided data |  1.1.0-1.1.0   |
| `.spec.reenrollmentOnRenew`               | Determines whether during renewal, certificate should be re-enrolled instead of renewed                                                                                                                                                                                         |  1.0.1-1.0.0   |
| `.spec.profileId`                         | Entity profile ID in NCM, optional; needs to be in double quotes                                                                                                                                                                                                                |  1.0.1-1.0.0   |
| `.spec.noRoot`                            | Determines whether issuing CA certificate should be included in issued certificate CA field (ca.crt) instead of root CA certificate                                                                                                                                             |  1.0.1-1.0.0   |
| `.spec.chainInSigner`                     | Determines whether certificate chain should be included in issued certificate CA field (ca.crt - root CA certificate + intermediate CA certificates + singing CA certificate)                                                                                                   |  1.0.3-1.0.2   |
| `.spec.onlyEECert`                        | Determines whether only end-entity certificate should be included in issued certificate TLS field (tls.crt)                                                                                                                                                                     |  1.0.3-1.0.2   |

**:x: Deprecated:** The following fields are not recommended to be used anymore!

| Field                 | Description                                                                                                      | Supported from |
|:----------------------|:-----------------------------------------------------------------------------------------------------------------|:--------------:|
| `.spec.CASNAME`       | Name of an existing CA in the NCM, which will be used to issue certificates                                      |  1.0.1-1.0.0   |
| `.spec.CASHREF`       | Unique HREF identifier for existing CA in the NCM, which will be used to issue certificates                      |  1.0.1-1.0.0   |
| `.spec.ncmSERVER`     | The URL to the main NCM REST API                                                                                 |  1.0.1-1.0.0   |
| `.spec.ncmSERVER2`    | The URL to the backup NCM REST API in case of the lack of connection to the main one                             |  1.0.3-1.0.2   |
| `.spec.SecretName`    | The name of Secret which contains the credentials (user and password) needed for making requests to NCM REST API |  1.0.1-1.0.0   |
| `.spec.authNameSpace` | The name of namespace in which Secret to NCM REST API credentials can be found                                   |  1.0.1-1.0.0   |
| `.spec.tlsSecretName` | The name of Secret which contains CA bundle used to verify connections to the NCM REST API                       |  1.0.1-1.0.0   |

## Usage

### Create an Issuer

Once the deployment is up and running, you are ready to create your first `Issuer`!

<img src="./assets/creating-issuer.gif" alt="creating-issuer" />

The following is an example `Issuer` created for the namespace `example-ncm-ns`:

  ```bash
  $ cat << EOF | kubectl apply -f -
  apiVersion: certmanager.ncm.nokia.com/v1
  kind: Issuer
  metadata:
    name: example-ncm-issuer
    namespace: example-ncm-ns
  spec:
    caName: ncm-ca
    provisioner:
      mainAPI: https://nokia-ncm.local
      authRef:
        name: ncm-rest-auth
        namespace: example-ncm-ns
  EOF
  ```

After creating the `Issuer`, we should now be able to check its status:

  ```bash
  $ kubectl get ncmissuers -n example-ncm-ns
  NAME                 AGE   READY   REASON     MESSAGE
  example-ncm-issuer   3s    True    Verified   Signing CA verified and ready to sign certificates
  ```

The above output tells us that our `Issuer` is ready to sign certificates!

### Signing certificate

Once the `Issuer` was successfully created, it is now time to sign the first certificate:

<img src="./assets/signing-certificate.gif" alt="signing-certificate" />

  ```bash
  $ cat << EOF | kubectl apply -f -
  apiVersion: cert-manager.io/v1
  kind: Certificate
  metadata:
    name: example-ncm-certificate
    namespace: example-ncm-ns
  spec:
    commonName: example-ncm-certificate-nokia-ncm.local
    dnsNames:
    - example-ncm-certificate-nokia-ncm.local
    subject:
      countries:
      - PL
      organizationalUnits:
      - Security
      organizations:
      - Nokia
    usages:
    - server auth
    - data encipherment
    secretName: example-ncm-certificate-nokia-ncm-tls
    issuerRef:
      group: certmanager.ncm.nokia.com
      kind: Issuer
      name: example-ncm-issuer
  EOF
  ```

Then we can check the status of our newly issued certificate:

  ```bash
  $ kubectl get certificates -n example-ncm-ns
  NAME                      READY   SECRET                                  AGE
  example-ncm-certificate   True    example-ncm-certificate-nokia-ncm-tls   17s
  ```

and whether it has corresponding Secret referenced:

  ```bash
  $ kubectl get secrets -n example-ncm-ns
  NAME                                    TYPE                                  DATA   AGE
  default-token-g2f47                     kubernetes.io/service-account-token   3      18m
  example-ncm-certificate-details         Opaque                                1      22s
  example-ncm-certificate-nokia-ncm-tls   kubernetes.io/tls                     3      22s
  ```

Additionally, in NCM GUI we can also find our newly issued certificate.

### Renewing or reenrolling certificate

When it comes to renewing or reenrolling certificates, ncm-issuer will take care of this and
do it before the certificate expires (the renewal grace period
depends on the defined values in `Certificate` resource).

You can define what operation ncm-issuer should perform in such a case by
setting certain PK rotation policy in `Certificate` resource.

|               Field               |  Operation   |             Value             |
|:---------------------------------:|:------------:|:-----------------------------:|
| `.spec.privateKey.rotationPolicy` | Reenrollment |           "Always"            |
| `.spec.privateKey.rotationPolicy` |   Renewal    | "Never" or not even specified |

**:loudspeaker: Attention:** There is also an option for enforcing the reenrollment on
renewal in the definition of `Issuer` or `ClusterIssuer` resource. To do this simply set `.spec.reenrollmentOnRenew`
to **true** in `Issuer` or `ClusterIssuer` definition.

However, you can also trigger renewal or reenrolling operation manually using one of the commands below.

In case you have cert-manager kubectl plugin:

  ```bash
  $ kubectl cert-manager renew <certificate> -n <namespace>
  ```

In case you use cmctl:

  ```bash
  $ cmctl renew <certificate> -n <namespace>
  ```

## Troubleshooting

In case of any problem, besides checking the status of created resources,
you can also check the `ncm-issuer` pod logs:

  ```bash
  $ kubectl -n ncm-issuer logs -f `kubectl get pods -A -l app=ncm-issuer -o jsonpath='{.items[0].metadata.name}'`
  ```

If you deployed troubleshooting sidecar as well, you can check the `ncm-issuer` pod logs this way:

  ```bash
  $ kubectl -n ncm-issuer logs -c ncm-issuer -f `kubectl get pods -A -l app=ncm-issuer -o jsonpath='{.items[0].metadata.name}'`
  ```

In the case you want to increase logging verbosity level, change the `logging.logLevel` in `values.yaml` to
the desired value and update your deployment. To get all possible log messages, simply set the
`logging.logLevel` to **3**, you can also additionally change the `logging.stacktraceLevel` to
`error`.

There is also the possibility of using sidecar for troubleshooting purposes - just change the value of
`sidecar.enabled` to **true** in `values.yaml` and update your deployment.

<p align="right">(<a href="#top">back to top</a>)</p>
