package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	namespace = "ncm_issuer"
)

var (
	// CertificateRequestTotal is a prometheus metrics which holds the total number
	// of certificate requests.
	CertificateRequestTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_request_total",
		Help:      "The total number of certificate requests",
	}, []string{"requestType"})

	// CertificateRequestSuccesses is a prometheus metrics which holds the total number
	// of succeeded certificate requests.
	CertificateRequestSuccesses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_request_successes_total",
		Help:      "The total number of succeeded certificate requests",
	}, []string{"requestType"})

	// CertificateRequestFails is a prometheus metrics which holds the total number
	// of failed certificate requests.
	CertificateRequestFails = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_request_fails_total",
		Help:      "The total numbers of failed certificate requests",
	}, []string{"requestType"})

	// CertificateRequestTime is a prometheus metrics which keeps track of the
	// duration of certificate request.
	CertificateRequestTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "certificate_request_time_seconds",
		Help:      "Length of time per certificate request",
	})
)

func init() {
	metrics.Registry.MustRegister(
		CertificateRequestTotal,
		CertificateRequestSuccesses,
		CertificateRequestFails,
		CertificateRequestTime)
}
