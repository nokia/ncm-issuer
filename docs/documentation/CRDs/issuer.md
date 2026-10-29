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
      # insecureSkipVerify disables server certificate verification (insecure, testing only).
      # insecureSkipVerify: false
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

> :material-tag: [1.2.2-1.2.2](../../release-notes/1.2.2.md)

| Field                                  | Description                                                                                                                       |
|:---------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------|
| `.spec.provisioner.insecureSkipVerify` | Disables verification of the NCM API server certificate for HTTPS connections. Insecure, intended only for testing. Default `false` |

> :material-tag: [1.1.0-1.1.0](../../release-notes/1.1.0.md)

| Field                                     | Description                                                                                                                                                                                                                                                                  |
|:------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `.spec.caName`                            | Name of an existing CA in the NCM, which will be used to issue certificates. The name must match exactly (required if `.spec.caID` is not specified) |
| `.spec.caID`                              | ID of an existing CA in the NCM, the last part of its href, which will be used to issue certificates (required if `.spec.caName` is not specified) |
| `.spec.provisioner.mainAPI`               | The URL to the main NCM API endpoint (always required)                                                                                                                                                                                                                       |
| `.spec.provisioner.backupAPI`             | The URL to the backup NCM API endpoint in case of the lack of connection to the main one                                                                                                                                                                                     |
| `.spec.provisioner.httpClientTimeout`     | Maximum amount of time that the HTTP client will wait for a response from NCM API before aborting the request                                                                                                                                                                |
| `.spec.provisioner.healthCheckerInterval` | The time interval between each NCM API health check                                                                                                                                                                                                                          |
| `.spec.provisioner.authRef`               | Reference to a `secret` containing the credentials (user and password) needed for making requests to NCM API (always required). A namespaced `Issuer` always reads it from its own namespace and ignores the `namespace` field |
| `.spec.provisioner.tlsRef`                | Reference to a `secret` containing the CA bundle (`cacert`) used to verify HTTPS connections to the NCM API, together with an optional client key and certificate (`key`, `cert`) for mTLS. When `cacert` is omitted, the server certificate is verified against the system trust store. A namespaced `Issuer` always reads it from its own namespace and ignores the `namespace` field |

> :material-tag: [1.0.3-1.0.2](../../release-notes/1.0.3.md)

| Field                 | Description                                                                                                                                                                     |
|:----------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `.spec.chainInSigner` | Determines whether certificate chain should be included in issued certificate CA field (`ca.crt` - root CA certificate + intermediate CA certificates + singing CA certificate) |
| `.spec.onlyEECert`    | Determines whether only end-entity certificate should be included in issued certificate TLS field (`tls.crt`)                                                                   |

> :material-tag: [1.0.1-1.0.0](../../release-notes/1.0.1.md)

| Field                       | Description                                                                                                                           |
|:----------------------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| `.spec.reenrollmentOnRenew` | Deprecated, use `privateKey.rotationPolicy` in the `Certificate` instead. Forces re-enrollment for certificates that would otherwise be renewed through NCM `/update`, which happens only with `privateKey.rotationPolicy: Never` |
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
