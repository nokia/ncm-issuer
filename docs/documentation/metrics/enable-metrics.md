# How to see ncm-issuer metrics?

## Metrics purpose

The metrics implemented in the ncm-issuer are intended to reflect the actual number of requests for new certificate
or renewal operations sent to the NCM. It should be noted here that the `CertificateRequest` resource created by
the cert-manager and processed by ncm-issuer does not increment the metrics unless request is finally sent to the NCM
and a new request is created in the NCM. The same approach is used for the certificate renewal operations.

!!! example
    Let's assume that we have created a new `Certificate` resource and then cert-manager has created a new
    `CertificateRequest` for it, which is later processed by the ncm-issuer. At first no problems occurred, but it 
    turned out that there was no connection to the NCM API, ncm-issuer finished processing current `CertificateRequest`
    as it encountered error and cert-manger created new `CertificateRequest` resource. Does this mean that the metrics
    have been incremented? - No, as long as the request is not actually registered in NCM, none of the metrics 
    are incremented.

## Enabling ncm-issuer metrics

To see the ncm-issuer metrics, simply change the value of `prometheus.serviceMonitor.enabled` to **true** in
`values.yaml` and update your deployment. A service monitor for ncm-issuer should then be deployed, and the metrics
should be visible in Prometheus GUI. Ensure the default values set for `prometheus.serviceMonitor.selectorLabel` and
`prometheus.serviceMonitor.namespace` match your Prometheus configuration, if there are any differences change their
values accordingly to your configuration.

Below is an example configuration that enables ncm-issuer metrics - the Prometheus release is marked as `stable` and
it is deployed in `default` namespace:

  ```yaml title="values.yaml"
  prometheus:
  serviceMonitor:
    enabled: true
    selectorLabel: stable
    namespace: default
  ```

## Metrics types

`ncm_issuer_certificate_enrollment_total` - a prometheus metrics which holds the total number of enrollment 
operations, equivalent to the action of sending CSR to the NCM.

`ncm_issuer_certificate_enrollment_success_total` - a prometheus metrics which holds the total number of succeeded
enrollment operations.

`ncm_issuer_certificate_enrollment_fail_total` - a prometheus metrics which holds the total number of failed enrollment 
operations. The failure of this operation may have been due to encountered errors or CSR status in the NCM indicating 
rejection or postponement (ncm-issuer treats these statuses as not expected ones, which results in the failure of 
enrollment operation).

`ncm_issuer_certificate_renewal_total` - a prometheus metrics which holds the total number of renewal operation 
performed by ncm-issuer with usage of NCM.

`ncm_issuer_certificate_renewal_sucess_total` - a prometheus metrics which holds the total number of succeeded renewal 
operation performed by ncm-issuer with usage of NCM.

`ncm_issuer_certificate_renewal_fail_total` - a prometheus metrics which holds the total number of failed renewal 
operation performed by ncm-issuer with usage of NCM. The failure of this operation may have been due to an error
in k8s API, a missing certificate details secret or an NCM API error.