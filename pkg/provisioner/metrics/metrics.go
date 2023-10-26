/*
Copyright 2023 Nokia

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	namespace = "ncm_issuer"
)

var (
	// CertificateEnrollmentTotal is a prometheus metrics which holds the total
	// number of enrollment operations, equivalent to the action of sending CSR
	// to the NCM.
	CertificateEnrollmentTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_enrollment_total",
		Help:      "The total number of enrollment operations",
	})

	// CertificateEnrollmentSuccess is a prometheus metrics which holds the total
	// number of succeeded enrollment operations.
	CertificateEnrollmentSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_enrollment_success_total",
		Help:      "The total number of succeeded enrollment operations",
	})

	// CertificateEnrollmentFail is a prometheus metrics which holds the total
	// number of failed enrollment operations. The failure of this operation
	// may have been due to encountered errors or CSR status in the NCM
	// indicating rejection or postponement (ncm-issuer treats these statuses
	// as not expected ones, which results in the failure of enrollment operation).
	CertificateEnrollmentFail = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_enrollment_fail_total",
		Help:      "The total number of failed enrollment operations",
	})

	// CertificateRenewalTotal is a prometheus metrics which holds the total
	// number of renewal operation performed by ncm-issuer with usage of
	// NCM.
	CertificateRenewalTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_renewal_total",
		Help:      "The total number of renewal operations",
	})

	// CertificateRenewalSuccess is a prometheus metrics which holds the total
	// number of succeeded renewal operation performed by ncm-issuer with usage
	// of NCM.
	CertificateRenewalSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_renewal_success_total",
		Help:      "The total number of succeeded renewal operations",
	})

	// CertificateRenewalFail is a prometheus metrics which holds the total
	// number of failed renewal operation performed by ncm-issuer with usage
	// of NCM. The failure of this operation may have been due to an error
	// in k8s API, a missing certificate details secret or an NCM API error.
	CertificateRenewalFail = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_renewal_fail_total",
		Help:      "The total number of failed renewal operations",
	})
)

func init() {
	metrics.Registry.MustRegister(
		CertificateEnrollmentTotal,
		CertificateEnrollmentSuccess,
		CertificateEnrollmentFail,
		CertificateRenewalTotal,
		CertificateRenewalSuccess,
		CertificateRenewalFail,
	)
}
