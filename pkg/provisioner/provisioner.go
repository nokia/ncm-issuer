package provisioner

import (
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

type ExternalProvisioner interface {
	Sign(cr *cmapi.CertificateRequest) ([]byte, []byte, string, error)
	Renew(cr *cmapi.CertificateRequest, certID string) ([]byte, []byte, string, error)
}
