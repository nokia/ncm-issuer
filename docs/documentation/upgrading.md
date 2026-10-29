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

Save the values passed at installation or the last upgrade and compare them with the `values.yaml` of the new chart:

  ```bash
  helm get values ncm-issuer -n ncm-issuer -o yaml > my-values.yaml
  ```

`helm get values` shows only values passed with `-f` or `--set`. If you installed from a release archive
and edited the chart's own `values.yaml`, compare that file with the `values.yaml` of the original archive
and copy the changed settings into `my-values.yaml`. Do this before you extract the new archive over the old
one. `helm get values ncm-issuer -n ncm-issuer --all` shows every value the running release uses.

If `my-values.yaml` sets `image.tag` or `sidecar.tag`, change them to the target version or remove them.
Otherwise the old images keep running.

## Running the upgrade

From the public Helm chart repository, with the chart version of the target release (for example
`1.3.0-chart`):

  ```bash
  helm repo update
  helm upgrade ncm-issuer nokia/ncm-issuer --version <chart-version> --namespace ncm-issuer -f my-values.yaml
  ```

From a release archive (offline installation), extract the archive in an empty directory and push the
controller image to your registry. The archive holds only the controller image, built for `linux/amd64`. If
you use the troubleshooting sidecar, also download `ncm-issuer-utils-<version>.tgz` from the release and push
it the same way.

  ```bash
  tar xzf ncm-issuer-<version>-<version>.tar.gz
  docker load -i ncm-issuer/images/ncm-issuer-<version>.tgz
  docker tag ghcr.io/nokia-steward/ncm-issuer:<version> <registry>/ncm-issuer:<version>
  docker push <registry>/ncm-issuer:<version>
  ```

Set `image.repository` and `image.tag` (and `sidecar.repository` and `sidecar.tag`) in `my-values.yaml` to
the pushed images. If the file already has an `image` or `sidecar` block, change it instead of adding a
second one, because Helm uses only the last one. Then upgrade from the extracted chart:

  ```bash
  helm upgrade ncm-issuer ./ncm-issuer/charts/ncm-issuer --namespace ncm-issuer -f my-values.yaml
  ```

!!! note
    Pass your values with `-f` or, on Helm 3.14 or later, with `--reset-then-reuse-values`. Do not
    use `--reuse-values`. It keeps the values of the installed chart, including its image tags. When
    the installed version is 1.2.0 or later, the upgrade succeeds but the old images keep running.
    From older versions the new chart fails to render with an error such as
    `nil pointer evaluating interface {}.httpProxy`. Copying an old `values.yaml` over the one that
    ships with the new chart has the same effect, so edit the new file instead.

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
  fail with `cannot change roleRef` (`roleRef: Invalid value: ...: field is immutable` on Kubernetes
  1.37). For them, set `certManagerRbac.role` to the existing name:

    ```bash
    kubectl get clusterrolebinding cert-manager-controller-approve:ncm-certmanager-nokia-com -o jsonpath='{.roleRef.name}'
    ```

**1.2.1**

* The chart's `securityContext` now applies only to the controller container. Pod-level settings
  moved to `podSecurityContext` and the troubleshooting sidecar has its own `sidecar.securityContext`.
  Move existing overrides accordingly.
* The NCM health check now sends `GET /v1/cas` and counts only `2xx` responses as healthy. The
  issuer's `Ready` condition depends on it. A wrong URL or wrong credentials that earlier versions
  reported as `Ready=True` now give `Ready=False`.
* Remove any path after the host and port from `mainAPI`. Requests to the main API ignore it, but the
  health check calls `<mainAPI>/v1/cas` and fails if NCM does not answer there.
* The default images moved from `docker.io/misiektoja` to `ghcr.io/nokia`.
* Kubernetes 1.26 or later is required. Helm refuses to install or upgrade the chart on older clusters.

**1.2.2**

* HTTPS connections to NCM verify the server certificate by default. If the NCM certificate is
  signed by a private CA, add that CA as `cacert` to the Secret referenced by `tlsRef` (see
  [TLS without client authentication](configuration.md#tls-without-client-authentication)).
  Otherwise the issuer reports `Ready=False` with `x509: certificate signed by unknown authority`.
  The certificate must also list the host name or IP address used in the URL as a subject
  alternative name. Certificates that carry the name only in the subject CN are rejected.
* A namespaced `Issuer` reads the Secrets referenced by `authRef` and `tlsRef` only from its own
  namespace and ignores the `namespace` field. Copy Secrets kept elsewhere into the Issuer's
  namespace, otherwise it reports `Ready=False` with reason `SecretNotFound`. `ClusterIssuer` is
  not affected.

**1.3.0**

* The chart repository and the images moved to the `nokia-steward` organization. Repoint the Helm
  repository (see [From the public Helm chart repository](installation.md#from-the-public-helm-chart-repository-recommended))
  Change any `image.repository` or `sidecar.repository` override that points to `ghcr.io/nokia` or
  `docker.io/misiektoja` to `ghcr.io/nokia-steward/ncm-issuer` and `ghcr.io/nokia-steward/ncm-issuer-utils`.
  Update registry mirrors that copy from the old locations as well.
