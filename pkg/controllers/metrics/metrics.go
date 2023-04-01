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
	CertificateRequestTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_request_total",
		Help:      "The total number of certificate requests",
	})

	// CertificateRequestSuccesses is a prometheus metrics which holds the total number
	// of succeeded certificate requests. Type refers to type of operation that
	// would be performed i.e. unrecognised, enrollment, renewal. Unrecognised
	// type exists due to the need to perform actions for recognise the type of
	// operation and that actions may fail.
	CertificateRequestSuccesses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_request_successes_total",
		Help:      "The total number of succeeded certificate requests",
	}, []string{"type"})

	// CertificateRequestFails is a prometheus metrics which holds the total number
	// of failed certificate requests. Type refers to type of operation
	// that would be performed i.e. unrecognised, enrollment, renewal. Unrecognised
	// type exists due to the need to perform actions for recognise the type of
	// operation and that actions may fail. Retry determines whether a new attempt
	// at processing certificate request will be made despite failure.
	CertificateRequestFails = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "certificate_request_fails_total",
		Help:      "The total number of failed certificate requests",
	}, []string{"type", "retry"})

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
