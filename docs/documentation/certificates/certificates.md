# Renewing or re-enrolling

When it comes to renewing or re-enrolling certificates, ncm-issuer will take care of this and
do it before the certificate expires (the renewal grace period
depends on the defined values in `Certificate` resource).

You can define what operation ncm-issuer should perform in such a case by
setting certain PK rotation policy in the `Certificate` resource.

|               Field               |  Operation   |                        Value                        |
|:---------------------------------:|:------------:|:---------------------------------------------------:|
| `.spec.privateKey.rotationPolicy` | Re-enrollment | `Always` or **field omitted**                     |
| `.spec.privateKey.rotationPolicy` |   Renewal    | `Never` (**must be set explicitly**)              |

!!! attention
    From **ncm-issuer 1.1.8** onwards, omitting `.spec.privateKey.rotationPolicy`
    means **re-enrollment** (private key rotation) instead of renewal. This aligns ncm-issuer behaviour with
    cert-manager **v1.18.0+**, where the default rotation policy changed from `Never` to `Always`.
    If you require a true renew-with-same-key flow, set `.spec.privateKey.rotationPolicy` to `Never` explicitly.

!!! note
    There is also an option for enforcing the re-enrollment on
    renewal in the definition of `Issuer` or `ClusterIssuer` resource. To do this simply set `.spec.reenrollmentOnRenew`
    to **true** in `Issuer` or `ClusterIssuer` definition.

However, you can also trigger renewal or re-enrolling operation manually using one of the commands below.

In case you use [cmctl](https://cert-manager.io/docs/reference/cmctl/):

  ```bash
  $ cmctl renew <certificate> -n <namespace>
  ```

  In case you have [cert-manager kubectl plugin](https://cert-manager.io/docs/reference/cmctl/#kubectl-plugin):

  ```bash
  $ kubectl cert-manager renew <certificate> -n <namespace>
  ```
