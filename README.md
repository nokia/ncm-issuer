<!-- markdownlint-disable  MD013 MD014 MD033 -->
<div id="top"></div>

# NCM-ISSUER

![Release](https://img.shields.io/github/v/release/nokia/ncm-issuer)
![Build version](https://img.shields.io/docker/v/misiektoja/ncm-issuer/latest?label=build-version)

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=nokia_ncm-issuer)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=nokia_ncm-issuer&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=nokia_ncm-issuer)
[![Go Report Card](https://goreportcard.com/badge/github.com/nokia/ncm-issuer)](https://goreportcard.com/report/github.com/nokia/ncm-issuer)

<div style="text-align:center">
   <img src="./assets/ncm-issuer-logo.png" alt="ncm-issuer-logo" width="35%"/>
</div>

NCM-ISSUER is a [Kubernetes](https://kuberenets.io) controller (external [cert-manager](https://cert-manager.io/) issuer) that allows to integrate with 
[Nokia Netguard Certificate Manager (NCM)](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/)
PKI system to sign certificate requests. The use of integration with NCM makes it easy to obtain certificates for
applications and to ensure that they are valid and up to date.

## Table of contents

* [Prerequisites](#prerequisites)
* [Installation and configuration](#installation-and-configuration)
  * [Installing using Helm](#installing-using-helm)
    * [Using own (local or remote) registry](#using-own--local-or-remote--registry)
  * [Configuration](#configuration)
    * [NCM API credentials](#ncm-api-credentials)
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

## Prerequisites
Prerequisites for building and using NCM-ISSUER:

* [NCM](https://www.nokia.com/networks/products/pki-authority-with-netguard-certificate-manager/) release 21 or later,
* [Kubernetes](https://kuberenets.io) version 1.18 or later,
* [cert-manager](https://cert-manager.io/) version 1.0.0 or later,
* [Docker](https://docs.docker.com/engine/install/) version 20.10.0 or later,
* [Helm](https://helm.sh/docs/intro/install/) v3.

**:warning: Warning:** Install docker-re instead of default if you are using CentOS, RedHat or Fedora!

## Installation and configuration

### Installing using Helm
The easiest way to install NCM-ISSUER in Kubernetes cluster is to use Helm.

At the very beginning it is necessary to create namespace for NCM-ISSUER:
```bash
$ kubectl create namespace ncm-issuer
```

And then install it using the command:
```bash
$ helm install ncm-issuer -n ncm-issuer ./helm/.
```

On the other hand, if you did not use `git`, but downloaded the packaged version of NCM-ISSUER use:
```bash
$ helm install ncm-issuer -n ncm-issuer ./ncm-issuer/charts/ncm-issuer/.
```

#### Using own (local or remote) registry
In case you want to use your own registry, just change the value pointing to a specific registry
in the `values.yaml` file in directory that contains Helm files. Then just repeat the steps
mentioned above.

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
To make the NCM-ISSUER work properly, it is necessary to create few Kubernetes secrets
that contains credentials to NCM API and TLS configuration.

#### NCM API credentials
```bash
$ kubectl create secret generic SECRET-NAME -n NAMESPACE --from-literal=username=USERNAME --from-literal=usrPassword=PASSWORD
```

#### TLS without client authentication
```bash
$ kubectl create -n NAMESPACE secret generic SECRET-NAME --from-file=cacert=CA-FOR-REST-API.pem
```

#### TLS with client authentication
```bash
$ kubectl create -n NAMESPACE secret generic SECRET-NAME --from-file=cacert=CA-FOR-REST-API.pem --from-file=key=CLIENT-AUTH-PKEY.pem --from-file=cert=CLIENT-AUTH-CERT.pem
```

To make sure that specific secret have been created correctly, you can check this
by using command:
```bash
$ kubectl -n NAMESPACE describe secrets SECRET-NAME
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
  caName: ncm-ca
  caID: e1DefAscx
  provisioner:
    mainAPI: https://nokia-ncm.local
    backupAPI: https://nokia-backup-ncm.local
    httpClientTimeout: 10s
    healthCheckerInterval: 1m
    authRef:
      name: ncm-rest-auth
      namespace: ncm-ns
    tlsRef:
      name: ncm-tls
      namespace: ncm-ns
  profileId: 101
  useProfileIDForRenew: true
  noRoot: true
  littleEndian: true
  chainInSigner: false
  onlyEECert: true
```

**:warning: Warning:** With release `1.0.4-1.1.0` the name of some fields in `Issuer` has changed, but old names are
still supported and can be used (this applies to: `CASNAME`, `CASHREF`, `ncmSERVER`, `ncmSERVER2`, `secretName`,
`tlsSecretName`, `authNameSpace`).

### ClusterIssuer resource
With the `ClusterIssuer`, the definition does not differ from that presented
with `Issuer`, and the only differences are in the field `kind` and the non-existence of field
`.metadata.namspace` for `Cluster` scope reasons.

```yaml
apiVersion: certmanager.ncm.nokia.com/v1
kind: ClusterIssuer
metadata:
  name: example-ncm-clusterissuer
spec:
  ...
```

### Issuer and ClusterIssuer fields overview

| Field                                     | Description                                                                                                                                                                                                                                                                | Supported from |
|:------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------:|
| `.spec.caName`                            | Name of an existing CA in the NCM API, which will be used to issue certificates                                                                                                                                                                                            |  1.0.4-1.1.0   |
| `.spec.caID`                              | Unique identifier for existing CA in the NCM API, which will be used to issue certificates                                                                                                                                                                                 |  1.0.4-1.1.0   |
| `.spec.provisioner.mainAPI`               | The URL to the main NCM API                                                                                                                                                                                                                                                |  1.0.4-1.1.0   |
| `.spec.provisioner.backupAPI`             | The URL to the backup NCM API in case of the lack of connection to the main one                                                                                                                                                                                            |  1.0.4-1.1.0   |
| `.spec.provisioner.httpClientTimeout`     | Maximum amount of time that the HTTP client will wait for a response from NCM API before aborting the request                                                                                                                                                              |  1.0.4-1.1.0   |
| `.spec.provisioner.healthCheckerInterval` | The time interval between each NCM API health check                                                                                                                                                                                                                        |  1.0.4-1.1.0   |
| `.spec.provisioner.authRef`               | Reference to a Secret containing the credentials (user and password) needed for making requests to NCM API                                                                                                                                                                 |  1.0.4-1.1.0   |
| `.spec.provisioner.tlsRef`                | Reference to a Secret containing CA bundle used to verify connections to the NCM API. If the secret reference is not specified and selected protocol is HTTPS, InsecureSkipVerify will be used. Otherwise, TLS or mTLS connection will be used, depending on provided data |  1.0.4-1.1.0   |
| `.spec.profileId`                         | Entity profile ID in NCM API                                                                                                                                                                                                                                               |  1.0.1-1.0.0   |
| `.spec.noRoot`                            | Determines whether issuing CA certificate should be included in issued certificate CA field instead of root CA certificate                                                                                                                                                 |  1.0.1-1.0.0   |
| `.spec.littleEndian`                      | LittleEndian specifies the byte order, setting it to true will ensure that bytes are stored in LE order otherwise BE order will be used                                                                                                                                    |  1.0.1-1.0.0   |
| `.spec.chainInSigner`                     | Determines whether certificate chain should be included in issued certificate CA field (intermediate certificates + singing CA certificate + root CA certificate)                                                                                                          |  1.0.3-1.0.2   |
| `.spec.onlyEECert`                        | Determines whether only end-entity certificate should be included in issued certificate TLS field                                                                                                                                                                          |  1.0.3-1.0.2   |

**:x: Deprecated:** The following fields are not recommended to be used!

| Field                       | Description                                                                                                 | Supported from |
|:----------------------------|:------------------------------------------------------------------------------------------------------------|:--------------:|
| `.spec.CASNAME`             | Name of an existing CA in the NCM API, which will be used to issue certificates                             |  1.0.1-1.0.0   |
| `.spec.CASHREF`             | Unique identifier for existing CA in the NCM API, which will be used to issue certificates                  |  1.0.1-1.0.0   |
| `.spec.ncmSERVER`           | The URL to the main NCM API                                                                                 |  1.0.1-1.0.0   |
| `.spec.ncmSERVER2`          | The URL to the backup NCM API in case of the lack of connection to the main one                             |  1.0.3-1.0.2   |
| `.spec.SecretName`          | The name of Secret which contains the credentials (user and password) needed for making requests to NCM API |  1.0.1-1.0.0   |
| `.spec.authNameSpace`       | The name of namespace in which Secret to NCM API credentials can be found                                   |  1.0.1-1.0.0   |
| `.spec.tlsSecretName`       | The name of Secret which contains CA bundle used to verify connections to the NCM API                       |  1.0.1-1.0.0   |
| `.spec.reenrollmentOnRenew` | Determines whether during renewal, certificate should be re-enrolled instead of renewed                     |  1.0.1-1.0.0   |

## Usage

### Create an Issuer
Once the deployment is up and running, you are ready to create your first `Issuer`!

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
  usage:
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

and whether it has been exported to referenced Secret:
```bash
$ kubectl get secrets -n example-ncm-ns
NAME                                    TYPE                                  DATA   AGE
default-token-g2f47                     kubernetes.io/service-account-token   3      18m
example-ncm-certificate-details         Opaque                                1      22s
example-ncm-certificate-nokia-ncm-tls   kubernetes.io/tls                     3      22s
```
Additionally, in NCM GUI we can also find our newly issued certificate.

### Renewing or reenrolling certificate
When it comes to renewing or reenrolling certificates, NCM-ISSUER will take care of this and
do it earlier enough before the certificate expires (the timing of chosen operation, 
depends on the defined values in `Certificate` resource).

You can define what operation NCM-ISSUER should perform in such a case by
setting certain PK rotation policy in `Certificate` resource.

|               Field               |  Operation   |             Value             |
|:---------------------------------:|:------------:|:-----------------------------:|
| `.spec.privateKey.rotationPolicy` | Reenrollment |           "Always"            |
| `.spec.privateKey.rotationPolicy` |   Renewal    | "Never" or not even specified |

However, you can also trigger renewal or reenrolling operation manually using the command:
```bash
$ kubectl cert-manager renew certificate-name -n namespace-name
```

## Troubleshooting
In case of any problem, besides checking the status of created resources,
you can also check the `ncm-issuer` pod logs:
```bash
$ kubectl -n ncm-issuer logs -f `kubectl get pods -A -l app=ncm-issuer -o jsonpath='{.items[0].metadata.name}'`
```

<p align="right">(<a href="#top">back to top</a>)</p>