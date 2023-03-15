package unit

import (
	"fmt"
	"strings"

	"github.com/nokia/ncm-issuer/pkg/ncmapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FakeClient struct {
	GetCAsFn                   func() (*ncmapi.CAsResponse, error)
	GetCAFn                    func(path string) (*ncmapi.CAResponse, error)
	SendCSRFn                  func(pem []byte, CA *ncmapi.CAResponse, profileID string) (*ncmapi.CSRResponse, error)
	CheckCSRStatusFn           func(path string) (*ncmapi.CSRStatusResponse, error)
	DownloadCertificateFn      func(path string) (*ncmapi.CertificateDownloadResponse, error)
	DownloadCertificateInPEMFn func(path string) ([]byte, error)
	RenewCertificateFn         func(path string, duration *metav1.Duration, profileID string) (*ncmapi.RenewCertificateResponse, error)
}

var _ ncmapi.ExternalClient = &FakeClient{}

func NewFakeClient(mods ...func(*FakeClient)) *FakeClient {
	fc := &FakeClient{}
	for _, mod := range mods {
		mod(fc)
	}
	return fc
}

func SetFakeClientGetCAs(r *ncmapi.CAsResponse, err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.GetCAsFn = func() (*ncmapi.CAsResponse, error) {
			return r, err
		}
	}
}

func SetFakeClientGetCA(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.GetCAFn = func(path string) (*ncmapi.CAResponse, error) {
			crtIdentifier := func() string {
				s := strings.Split(path, "/")
				return s[len(s)-1]
			}()

			return &ncmapi.CAResponse{
				Href:   fmt.Sprintf("https://ncm-server.local/cas/%s", crtIdentifier),
				Name:   crtIdentifier,
				Status: "active",
				Certificates: map[string]string{
					"active": fmt.Sprintf("https://ncm-servver-local/certificate/%s", crtIdentifier),
				},
			}, err
		}
	}
}

func SetFakeClientSendCSR(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.SendCSRFn = func(pem []byte, CA *ncmapi.CAResponse, profileID string) (*ncmapi.CSRResponse, error) {
			return &ncmapi.CSRResponse{
				Href: "https://ncm-server.local/requests/SaVye12",
			}, err
		}
	}
}

func SetFakeClientCSRStatus(status string, err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.CheckCSRStatusFn = func(path string) (*ncmapi.CSRStatusResponse, error) {
			crtIdentifier := func() string {
				s := strings.Split(path, "/")
				return s[len(s)-1]
			}()

			return &ncmapi.CSRStatusResponse{
				Href:        fmt.Sprintf("https://ncm-server.local/requests/%s", crtIdentifier),
				Certificate: "https://ncm-server.local/certificates/L34FC3RT",
				Status:      status,
			}, err
		}
	}
}

func SetFakeClientDownloadCertificate(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.DownloadCertificateFn = func(path string) (*ncmapi.CertificateDownloadResponse, error) {
			crtIdentifier := func() string {
				s := strings.Split(path, "/")
				return s[len(s)-1]
			}()

			return &ncmapi.CertificateDownloadResponse{
				Href:     fmt.Sprintf("https://ncm-server.local/certificates/%s", crtIdentifier),
				IssuerCA: fmt.Sprintf("https://ncm-server.local/cas/%s", crtIdentifier),
				Status:   "active",
			}, err
		}
	}
}

func SetFakeClientDownloadCertificateInPEM(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.DownloadCertificateInPEMFn = func(path string) ([]byte, error) {
			crtIdentifier := func() string {
				s := strings.Split(path, "/")
				return s[len(s)-1]
			}()

			return []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s...\n-----END CERTIFICATE-----\n", crtIdentifier)), err
		}
	}

}

func SetFakeClientRenewCertificate(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.RenewCertificateFn = func(path string, duration *metav1.Duration, profileID string) (*ncmapi.RenewCertificateResponse, error) {
			return &ncmapi.RenewCertificateResponse{
				Certificate: "https://ncm-server.local/certificates/L34FC3RT",
			}, err
		}
	}
}

func (fc *FakeClient) GetCAs() (*ncmapi.CAsResponse, error) {
	return fc.GetCAsFn()
}

func (fc *FakeClient) GetCA(path string) (*ncmapi.CAResponse, error) {
	return fc.GetCAFn(path)
}

func (fc *FakeClient) SendCSR(pem []byte, CA *ncmapi.CAResponse, profileID string) (*ncmapi.CSRResponse, error) {
	return fc.SendCSRFn(pem, CA, profileID)
}

func (fc *FakeClient) CheckCSRStatus(path string) (*ncmapi.CSRStatusResponse, error) {
	return fc.CheckCSRStatusFn(path)
}

func (fc *FakeClient) DownloadCertificate(path string) (*ncmapi.CertificateDownloadResponse, error) {
	return fc.DownloadCertificateFn(path)
}

func (fc *FakeClient) DownloadCertificateInPEM(path string) ([]byte, error) {
	return fc.DownloadCertificateInPEMFn(path)
}

func (fc *FakeClient) RenewCertificate(path string, duration *metav1.Duration, profileID string) (*ncmapi.RenewCertificateResponse, error) {
	return fc.RenewCertificateFn(path, duration, profileID)
}
