# Issuer

The first thing you need to configure and create after installing ncm-issuer is `Issuer` or `ClusterIssuer`. 
The `Issuer` or `ClusterIssuer` is considered as a representative of an existing certificate authority (CA) 
in the NCM that will issue certificates using it.

## Resource definition

Below is an example `yaml` file containing `Issuer` definition:

  ```yaml title="issuer.yaml"
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
    profileId: "101"
    useProfileIDForRenew: true
    reenrollmentOnRenew: true
    noRoot: true
    chainInSigner: false
    onlyEECert: true
  ```

!!! warning
    With release `1.1.0-1.1.0` the name of some fields in `Issuer` has changed, but old names are
    still supported and can be used (this applies to: `CASNAME`, `CASHREF`, `ncmSERVER`, `ncmSERVER2`, `secretName`,
    `tlsSecretName`, `authNameSpace`), but they are not recommended to be used anymore.

## Fields description

The number next to the label icon indicates from which version the fields are supported.

> :material-tag: [1.1.0-1.1.0](../../release-notes/1.1.0.md)

| Field                                     | Description                                                                                                                                                                                                                                                                  |
|:------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `.spec.caName`                            | Name of an existing CA in the NCM, which will be used to issue certificates                                                                                                                                                                                                  |
| `.spec.caID`                              | Unique href (or ID) identifier for existing CA in the NCM, which will be used to issue certificates                                                                                                                                                                          |
| `.spec.provisioner.mainAPI`               | The URL to the main NCM API endpoint                                                                                                                                                                                                                                         |
| `.spec.provisioner.backupAPI`             | The URL to the backup NCM API endpoint in case of the lack of connection to the main one                                                                                                                                                                                     |
| `.spec.provisioner.httpClientTimeout`     | Maximum amount of time that the HTTP client will wait for a response from NCM API before aborting the request                                                                                                                                                                |
| `.spec.provisioner.healthCheckerInterval` | The time interval between each NCM API health check                                                                                                                                                                                                                          |
| `.spec.provisioner.authRef`               | Reference to a `secret` containing the credentials (user and password) needed for making requests to NCM API                                                                                                                                                                 |
| `.spec.provisioner.tlsRef`                | Reference to a `secret` containing CA bundle used to verify connections to the NCM API. If the secret reference is not specified and selected protocol is HTTPS, InsecureSkipVerify will be used. Otherwise, TLS or mTLS connection will be used, depending on provided data |

> :material-tag: [1.0.3-1.0.2](../../release-notes/1.0.3.md)

| Field                 | Description                                                                                                                                                                     |
|:----------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `.spec.chainInSigner` | Determines whether certificate chain should be included in issued certificate CA field (`ca.crt` - root CA certificate + intermediate CA certificates + singing CA certificate) |
| `.spec.onlyEECert`    | Determines whether only end-entity certificate should be included in issued certificate TLS field (`tls.crt`)                                                                   |

> :material-tag: [1.0.1-1.0.0](../../release-notes/1.0.1.md)

| Field                       | Description                                                                                                                           |
|:----------------------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| `.spec.reenrollmentOnRenew` | Determines whether during renewal, certificate should be re-enrolled instead of renewed                                               |                                                                                                                                                                         
| `.spec.profileId`           | Entity profile ID in NCM                                                                                                              |                                                                                                                                                                                                                                           
| `.spec.noRoot`              | Determines whether issuing CA certificate should be included in issued certificate CA field (`ca.crt`) instead of root CA certificate | 

!!! Danger
    The following fields are not recommended to be used anymore!

    | Field                 | Description                                                                                                        |
    |:----------------------|:-------------------------------------------------------------------------------------------------------------------|
    | `.spec.CASNAME`       | Name of an existing CA in the NCM, which will be used to issue certificates                                        |
    | `.spec.CASHREF`       | Unique HREF identifier for existing CA in the NCM, which will be used to issue certificates                        |
    | `.spec.ncmSERVER`     | The URL to the main NCM API endpoint                                                                               |
    | `.spec.ncmSERVER2`    | The URL to the backup NCM API endpoint in case of the lack of connection to the main one                           |
    | `.spec.SecretName`    | The name of `secret` which contains the credentials (user and password) needed for making requests to NCM REST API |
    | `.spec.authNameSpace` | The name of namespace in which `secret` to NCM API credentials can be found                                        |
    | `.spec.tlsSecretName` | The name of `secret` which contains CA bundle used to verify connections to the NCM API                            |