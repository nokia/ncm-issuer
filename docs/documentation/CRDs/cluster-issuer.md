# ClusterIssuer

With the `ClusterIssuer`, the definition does not differ from that presented
with `Issuer`, and the only differences are in the field `kind` and the non-existence of field
`.metadata.namespace` due to `Cluster` scope reasons.

## Resource definition

Below is an example `yaml` file containing `ClusterIssuer` definition:

  ```yaml title="clusterissuer.yaml"
  apiVersion: certmanager.ncm.nokia.com/v1
  kind: ClusterIssuer
  metadata:
    name: example-ncm-clusterissuer
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

As mentioned above, the `ClusterIssuer` differs practically in nothing from the `Issuer`, so the description of
`Issuer` fields and their usage is also correct for it: [issuer fields description](issuer.md#fields-description).
