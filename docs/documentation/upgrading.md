# Upgrading

Upgrade ncm-issuer in place with `helm upgrade`. Helm updates the controller, its RBAC and the CRDs.
Existing `Issuer`, `ClusterIssuer` and `Certificate` resources and their Secrets are kept.

!!! warning
    Do not uninstall the chart or delete the ncm-issuer CRDs to upgrade. The CRDs are part of the
    chart, so removing them deletes every `Issuer` and `ClusterIssuer` in the cluster. Certificates
    then fail to renew until the issuers are created again.

## Before you upgrade

Read the release notes of every version between the installed one and the target and check the
[version-specific notes](#version-specific-notes) below. The installed chart version is shown by:

  ```bash
  helm list -n ncm-issuer
  ```

Save the values set at install time and compare them with the `values.yaml` of the new chart:

  ```bash
  helm get values ncm-issuer -n ncm-issuer -o yaml > my-values.yaml
  ```

## Running the upgrade

From the public Helm chart repository, with the chart version of the target release (for example
`1.3.0-chart`):

  ```bash
  helm repo update
  helm upgrade ncm-issuer nokia/ncm-issuer --version <chart-version> --namespace ncm-issuer -f my-values.yaml
  ```

From a release archive (offline installation), push the images from `ncm-issuer/images/` to your
registry as described in [Using own (local or remote) registry](installation.md#using-own-local-or-remote-registry)
and upgrade from the extracted chart:

  ```bash
  helm upgrade ncm-issuer ./ncm-issuer/charts/ncm-issuer --namespace ncm-issuer -f my-values.yaml
  ```

!!! note
    Pass your values with `-f` or, on Helm 3.14 or later, with `--reset-then-reuse-values`. Do not
    use `--reuse-values`: it keeps the defaults of the installed chart, so a newer chart can fail to
    render. Upgrading from a version before 1.2.0 fails with
    `nil pointer evaluating interface {}.httpProxy`. For the same reason, if you customize the
    chart's own `values.yaml`, edit the file that ships with the new chart instead of copying the
    old one over it.

Check that the new controller is running and that every issuer reports `READY` `True`:

  ```bash
  helm list -n ncm-issuer
  kubectl -n ncm-issuer get pods
  kubectl get ncmclusterissuers
  kubectl get ncmissuers -A
  ```

For an issuer with `READY` `False` the `REASON` and `MESSAGE` columns say why. See also
[Troubleshooting](troubleshooting.md#issuer-stuck-in-readyfalse-with-ncm-api-health-check-failed).

To return to the previous release, run `helm rollback ncm-issuer --namespace ncm-issuer`. Issuers
and certificates are kept.

## Version-specific notes

Check every entry for the versions you upgrade across.

**1.2.0**

* The default name of the cert-manager approver ClusterRole lost a trailing `v` (`...nokia-comv`).
  `helm upgrade` keeps the name used by the existing ClusterRoleBinding, because its `roleRef` cannot
  change. Tools that render the chart with `helm template`, such as Argo CD, cannot look it up and
  fail with `cannot change roleRef`. For them, set `certManagerRbac.role` to the existing name:

    ```bash
    kubectl get clusterrolebinding cert-manager-controller-approve:ncm-certmanager-nokia-com -o jsonpath='{.roleRef.name}'
    ```

**1.2.1**

* The chart's `securityContext` now applies only to the controller container. Pod-level settings
  moved to `podSecurityContext` and the troubleshooting sidecar has its own `sidecar.securityContext`.
  Move existing overrides accordingly.
* The NCM health check now authenticates and accepts only `2xx` responses. A wrong URL or wrong
  credentials that earlier versions reported as `Ready=True` now give `Ready=False`.
* Kubernetes 1.26 or later is required. Helm refuses to install the chart on older clusters.

**1.2.2**

* HTTPS connections to NCM verify the server certificate by default. If the NCM certificate is
  signed by a private CA, add that CA as `cacert` to the Secret referenced by `tlsRef` (see
  [TLS without client authentication](configuration.md#tls-without-client-authentication)).
  Otherwise the issuer reports `Ready=False` with `x509: certificate signed by unknown authority`.
* A namespaced `Issuer` reads the Secrets referenced by `authRef` and `tlsRef` only from its own
  namespace and ignores the `namespace` field. Copy Secrets kept elsewhere into the Issuer's
  namespace, otherwise it reports `Ready=False` with reason `SecretNotFound`. `ClusterIssuer` is
  not affected.

**1.3.0**

* The chart repository and the images moved to the `nokia-steward` organization. Repoint the Helm
  repository (see [From the public Helm chart repository](installation.md#from-the-public-helm-chart-repository-recommended))
  and update registry mirrors and any `image.repository` or `sidecar.repository` override to
  `ghcr.io/nokia-steward/ncm-issuer` and `ghcr.io/nokia-steward/ncm-issuer-utils`.
