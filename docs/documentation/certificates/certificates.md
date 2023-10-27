# Renewing or re-enrolling

When it comes to renewing or re-enrolling certificates, ncm-issuer will take care of this and
do it before the certificate expires (the renewal grace period
depends on the defined values in `Certificate` resource).

You can define what operation ncm-issuer should perform in such a case by
setting certain PK rotation policy in `Certificate` resource.

|               Field               |   Operation   |             Value             |
|:---------------------------------:|:-------------:|:-----------------------------:|
| `.spec.privateKey.rotationPolicy` | re-enrollment |           "Always"            |
| `.spec.privateKey.rotationPolicy` |    renewal    | "Never" or not even specified |

!!! tip
    There is also an option for enforcing the re-enrollment on
    renewal in the definition of `Issuer` or `ClusterIssuer` resource. To do this simply set `.spec.reenrollmentOnRenew`
    to **true** in `Issuer` or `ClusterIssuer` definition.

However, you can also trigger renewal or re-enrolling operation manually using one of the commands below.

In case you have cert-manager kubectl plugin:

  ```bash
  kubectl cert-manager renew <certificate> -n <namespace>
  ```

In case you use cmctl:

  ```bash
  cmctl renew <certificate> -n <namespace>
  ```