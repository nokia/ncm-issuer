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

package gen

import (
	"fmt"
	"strings"
	"time"

	"github.com/nokia/ncm-issuer/pkg/ncmapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FakeClient struct {
	GetCAsFn                   func() (*ncmapi.CAsResponse, error)
	GetCAFn                    func(path string) (*ncmapi.CAResponse, error)
	SendCSRFn                  func() (*ncmapi.CSRResponse, error)
	CheckCSRStatusFn           func(path string) (*ncmapi.CSRStatusResponse, error)
	DownloadCertificateFn      func(path string) (*ncmapi.CertificateDownloadResponse, error)
	DownloadCertificateInPEMFn func(path string) ([]byte, error)
	RenewCertificateFn         func() (*ncmapi.RenewCertificateResponse, error)
}

func NewFakeClient(mods ...func(*FakeClient)) *FakeClient {
	fc := &FakeClient{}
	for _, mod := range mods {
		mod(fc)
	}
	return fc
}

func SetFakeClientGetCAs(r *ncmapi.CAsResponse) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.GetCAsFn = func() (*ncmapi.CAsResponse, error) {
			return r, nil
		}
	}
}

func SetFakeClientGetCAsError(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.GetCAsFn = func() (*ncmapi.CAsResponse, error) {
			return nil, err
		}
	}
}

func NoErrorFakeClientGetCA() func(*FakeClient) {
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
			}, nil
		}
	}
}

func SetFakeClientGetCAError(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.GetCAFn = func(path string) (*ncmapi.CAResponse, error) {
			return nil, err
		}
	}
}

func NoErrorFakeClientSendCSR() func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.SendCSRFn = func() (*ncmapi.CSRResponse, error) {
			return &ncmapi.CSRResponse{
				Href: "https://ncm-server.local/requests/it-doesnt-matter",
			}, nil
		}
	}
}

func SetFakeClientSendCSRError(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.SendCSRFn = func() (*ncmapi.CSRResponse, error) {
			return nil, err
		}
	}
}

func SetFakeClientCSRStatus(status string) func(*FakeClient) {
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
			}, nil
		}
	}
}

func SetFakeClientCSRStatusError(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.CheckCSRStatusFn = func(string) (*ncmapi.CSRStatusResponse, error) {
			return nil, err
		}
	}
}

func NoErrorFakeClientDownloadCertificate() func(*FakeClient) {
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
			}, nil
		}
	}
}

func SetFakeClientDownloadCertificateError(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.DownloadCertificateFn = func(string) (*ncmapi.CertificateDownloadResponse, error) {
			return nil, err
		}
	}
}

func NoErrorFakeClientDownloadCertificateInPEM() func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.DownloadCertificateInPEMFn = func(path string) ([]byte, error) {
			crtIdentifier := func() string {
				s := strings.Split(path, "/")
				return s[len(s)-1]
			}()

			return []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s...\n-----END CERTIFICATE-----\n", crtIdentifier)), nil
		}
	}
}

func SetFakeClientDownloadCertificateInPEMError(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.DownloadCertificateInPEMFn = func(string) ([]byte, error) {
			return nil, err
		}
	}
}

func SetFakeClientRenewCertificate(renewedCrtName string) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.RenewCertificateFn = func() (*ncmapi.RenewCertificateResponse, error) {
			return &ncmapi.RenewCertificateResponse{
				Certificate: fmt.Sprintf("https://ncm-server.local/certificates/%s", renewedCrtName),
			}, nil
		}
	}
}

func SetFakeClientRenewCertificateError(err error) func(*FakeClient) {
	return func(fc *FakeClient) {
		fc.RenewCertificateFn = func() (*ncmapi.RenewCertificateResponse, error) {
			return nil, err
		}
	}
}

func (fc *FakeClient) GetCAs() (*ncmapi.CAsResponse, error) {
	return fc.GetCAsFn()
}

func (fc *FakeClient) GetCA(path string) (*ncmapi.CAResponse, error) {
	return fc.GetCAFn(path)
}

func (fc *FakeClient) SendCSR([]byte, *ncmapi.CAResponse, string) (*ncmapi.CSRResponse, error) {
	return fc.SendCSRFn()
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

func (fc *FakeClient) RenewCertificate(string, *metav1.Duration, string) (*ncmapi.RenewCertificateResponse, error) {
	return fc.RenewCertificateFn()
}

func (fc *FakeClient) StartHealthChecker(interval time.Duration) {}

func (fc *FakeClient) StopHealthChecker() {}
