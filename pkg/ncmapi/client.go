package ncmapi

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ExternalClient interface {
	GetCAs() (*CAsResponse, error)
	GetCA(path string) (*CAResponse, error)
	SendCSR(pem []byte, CA *CAResponse, profileID string) (*CSRResponse, error)
	CheckCSRStatus(path string) (*CSRStatusResponse, error)
	DownloadCertificate(path string) (*CertificateDownloadResponse, error)
	DownloadCertificateInPEM(path string) ([]byte, error)
	RenewCertificate(path string, duration *metav1.Duration, profileID string) (*RenewCertificateResponse, error)
	StartHealthChecker(interval time.Duration)
	StopHealthChecker()
}
