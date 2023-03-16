package ncmapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	testr "github.com/go-logr/logr/testing"
	"github.com/nokia/ncm-issuer/pkg/cfg"
)

var (
	rootCA = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"

	certPEM = `-----BEGIN CERTIFICATE-----
MIIB2zCCAYWgAwIBAgIUKkV94DTD6al8iCukf+dVMUIzSFMwDQYJKoZIhvcNAQEL
BQAwQjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UE
CgwTRGVmYXVsdCBDb21wYW55IEx0ZDAeFw0yMzAzMTYxNDMyNTlaFw0yNDAzMTUx
NDMyNTlaMEIxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAa
BgNVBAoME0RlZmF1bHQgQ29tcGFueSBMdGQwXDANBgkqhkiG9w0BAQEFAANLADBI
AkEAwjCvS9h8ADaBz7jUayWB1Lcy6fcGeSD2u1qFmjtit4jGPjZkTNRD4qH22VLj
mqR43Cq4V++yTaEjT4HeetRDAwIDAQABo1MwUTAdBgNVHQ4EFgQU7feJQ8nAPPHw
KCtHx+rRAfX/LKswHwYDVR0jBBgwFoAU7feJQ8nAPPHwKCtHx+rRAfX/LKswDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAGqea1lWcEDRr7qrDGVKItJn
m7fvrww42l2LTJJ4nP9h6UBAmoSor0yHn7Zks/CTb9A/VTINB1sbP7n8USeOIxA=
-----END CERTIFICATE-----`

	keyPEM = `-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAwjCvS9h8ADaBz7jU
ayWB1Lcy6fcGeSD2u1qFmjtit4jGPjZkTNRD4qH22VLjmqR43Cq4V++yTaEjT4He
etRDAwIDAQABAkA6CBSKxPIhmihm7CRGtNm8uNa1RoYfsrMpQB8G/VI96FNXDnew
mWwruneVpm0DnRECEx4xO+DutB+mbSZv9WGJAiEA7XmFGZ+PlY31lXSKmsPWbDUQ
tLBzXbWQze8AceT8Yb0CIQDRVsDCHu8osESn+g4/Ak4MPuVpg4NBiqbo0DBRqDyj
vwIgIssFJ0XrgZv0+VrD2/0Jc30q325i2L37Y1C7HfTQzXkCIQCpobTdGJgPzpYz
z8sPf9yiy6y2zZzk1WffLCSbZsqMnQIhAKjl/vE+ekVi2Hb/yYNeqyxE24XQ1QC4
Fcw3AnfkJ3p2
-----END PRIVATE KEY-----`

	crt1 = CAResponse{
		Href:   "https://ncm-server.local/cas/Mn012Se",
		Name:   "ncmCA",
		Status: "active",
		Certificates: map[string]string{
			"active": "https://ncm-servver-local/certificate/Mn012Se",
		},
	}

	crt2 = CAResponse{
		Href:   "https://ncm-server.local/cas/eS210nM",
		Name:   "ncmCA2",
		Status: "active",
		Certificates: map[string]string{
			"active": "https://ncm-servver-local/certificate/eS210nM",
		},
	}

	crt3 = CAResponse{
		Href:         "https://ncm-server.local/cas/efG312Ed",
		Name:         "ncmCA3",
		Status:       "expired",
		Certificates: map[string]string{},
	}

	cas = CAsResponse{
		TotalCount: 3,
		Href:       "https://ncm-server.local/cas",
		CAList:     []CAResponse{crt1, crt2, crt3},
	}
)

func TestNewClientCreation(t *testing.T) {
	type testCase struct {
		name           string
		config         *cfg.NCMConfig
		err            error
		expectedClient *Client
	}

	CACertPool := x509.NewCertPool()
	CACertPool.AppendCertsFromPEM([]byte(rootCA))

	dir := os.TempDir()
	defer os.RemoveAll(dir)

	certFile, err := os.CreateTemp(dir, "ncm-testing-cert.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}
	certFile.Write([]byte(certPEM))

	certKey, err := os.CreateTemp(dir, "ncm-testing-cert-key.pem")
	if err != nil {
		t.Fatalf(err.Error())
	}
	certKey.Write([]byte(keyPEM))

	clientCert, _ := tls.LoadX509KeyPair(certFile.Name(), certKey.Name())

	run := func(t *testing.T, tc testCase) {
		c, err := NewClient(tc.config, &testr.TestLogger{})

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedClient != nil && !reflect.DeepEqual(tc.expectedClient, c) {
			t.Errorf("%s failed; created and expected client is not the same", tc.name)
		}
	}

	testCases := []testCase{
		{
			name: "Malformed main NCM API address",
			config: &cfg.NCMConfig{
				NCMServer: "https://ncm-server.local:-8081",
			},
			err:            errors.New("cannot create new API client"),
			expectedClient: nil,
		},
		{
			name: "Malformed backup NCM API address",
			config: &cfg.NCMConfig{
				NCMServer:  "https://ncm-server.local",
				NCMServer2: "https://ncm-backup-server.local:-8081",
			},
			err:            errors.New("cannot create new API client"),
			expectedClient: nil,
		},
		{
			name: "Cert & key file dont exist (mTLS connection)",
			config: &cfg.NCMConfig{
				NCMServer: "https://ncm-server.local",
				CACert:    rootCA,
				Key:       "ncm-certificate-key.pem",
				Cert:      "ncm-certificate.pem",
			},
			err:            errors.New("no such file or directory"),
			expectedClient: nil,
		},
		{
			name: "Successfully new client creation (insecure connection)",
			config: &cfg.NCMConfig{
				NCMServer: "http://ncm-server.local",
				Username:  "ncm-user",
				Password:  "ncm-user-password",
			},
			err: nil,
			expectedClient: &Client{
				NCMServer: "http://ncm-server.local",
				user:      "ncm-user",
				password:  "ncm-user-password",
				client: &http.Client{
					Timeout: DefaultHTTPTimeout * time.Second,
				},
				log: &testr.TestLogger{},
			},
		},
		{
			name: "Successfully new client creation (insecure skip verify)",
			config: &cfg.NCMConfig{
				NCMServer:          "https://ncm-server.local",
				Username:           "ncm-user",
				Password:           "ncm-user-password",
				InsecureSkipVerify: true,
			},
			err: nil,
			expectedClient: &Client{
				NCMServer: "https://ncm-server.local",
				user:      "ncm-user",
				password:  "ncm-user-password",
				client: &http.Client{
					Timeout: DefaultHTTPTimeout * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					},
				},
				log: &testr.TestLogger{},
			},
		},
		{
			name: "Successfully new client creation (TLS connection)",
			config: &cfg.NCMConfig{
				NCMServer: "https://ncm-server.local",
				Username:  "ncm-user",
				Password:  "ncm-user-password",
				CACert:    rootCA,
			},
			err: nil,
			expectedClient: &Client{
				NCMServer: "https://ncm-server.local",
				user:      "ncm-user",
				password:  "ncm-user-password",
				client: &http.Client{
					Timeout: DefaultHTTPTimeout * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							RootCAs: CACertPool,
						},
					},
				},
				log: &testr.TestLogger{},
			},
		},
		{
			name: "Successfully new client creation (mTLS connection)",
			config: &cfg.NCMConfig{
				NCMServer: "https://ncm-server.local",
				Username:  "ncm-user",
				Password:  "ncm-user-password",
				CACert:    rootCA,
				MTLS:      true,
				Cert:      certFile.Name(),
				Key:       certKey.Name(),
			},
			err: nil,
			expectedClient: &Client{
				NCMServer: "https://ncm-server.local",
				user:      "ncm-user",
				password:  "ncm-user-password",
				client: &http.Client{
					Timeout: DefaultHTTPTimeout * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							RootCAs:      CACertPool,
							Certificates: []tls.Certificate{clientCert},
						},
					},
				},
				log: &testr.TestLogger{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestValidateResponse(t *testing.T) {
	type testCase struct {
		name         string
		resp         *http.Response
		err          error
		expectedBody []byte
	}

	run := func(t *testing.T, tc testCase) {
		config := &cfg.NCMConfig{
			NCMServer: "https://ncm-server.local",
			Username:  "ncm-user",
			Password:  "ncm-user-password",
		}

		c, _ := NewClient(config, testr.TestLogger{})
		body, err := c.validateResponse(tc.resp)

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedBody != nil && !reflect.DeepEqual(tc.expectedBody, body) {
			t.Errorf("%s failed; received and wanted body is not the same", tc.name)
		}
	}

	testCases := []testCase{
		{
			name: "Successfully validate body returned by NCM API (status 200)",
			resp: &http.Response{
				StatusCode: 200,
				Body: io.NopCloser(bytes.NewBuffer(
					[]byte(`{"name": "ncmCA", "status": "active"}`))),
			},
			err:          nil,
			expectedBody: []byte(`{"name": "ncmCA", "status": "active"}`),
		},
		{
			name: "Successfully validate body returned by NCM API (status not 200)",
			resp: &http.Response{
				StatusCode: 500,
				Body: io.NopCloser(bytes.NewBuffer(
					[]byte(`{"message": "Internal Server Error", "status": 500, "statusMessage": "Internal Server Error"}`))),
			},
			err:          errors.New("500"),
			expectedBody: nil,
		},
		{
			name: "Unmarshalling json error",
			resp: &http.Response{
				StatusCode: 500,
				Body: io.NopCloser(bytes.NewBuffer(
					[]byte(`{"message": "Internal Server Error", "status": "500", "statusMessage": "Internal Server Error"}`))),
			},
			err:          errors.New("cannot unmarshal json"),
			expectedBody: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestGetCAs(t *testing.T) {
	type testCase struct {
		name        string
		handler     http.HandlerFunc
		err         error
		expectedCAs *CAsResponse
	}

	run := func(t *testing.T, tc testCase) {
		svr := httptest.NewServer(tc.handler)
		defer svr.Close()

		config := &cfg.NCMConfig{
			NCMServer: svr.URL,
			Username:  "ncm-user",
			Password:  "ncm-user-password",
		}

		c, _ := NewClient(config, testr.TestLogger{})
		cas, err := c.GetCAs()

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedCAs != nil && !reflect.DeepEqual(tc.expectedCAs, cas) {
			t.Errorf("%s failed; got %+v; want %+v", tc.name, cas, tc.expectedCAs)
		}
	}

	testCases := []testCase{
		{
			name: "Successfully get CAs from NCM API",
			handler: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(cas)
				}),
			err:         nil,
			expectedCAs: &cas,
		},
		{
			name: "NCM API returned internal server error",
			handler: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					apiError := APIError{
						Message:       "Internal Server Error",
						Status:        500,
						StatusMessage: "Internal Server Error",
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(apiError)
				}),
			err:         errors.New("500"),
			expectedCAs: nil,
		},
		{
			name: "Unmarshalling json error",
			handler: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					resp := map[string]string{
						"status": "500",
					}
					jsonResp, _ := json.Marshal(resp)

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write(jsonResp)
				}),
			err:         errors.New("cannot unmarshal json"),
			expectedCAs: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestGetCA(t *testing.T) {
	type testCase struct {
		name       string
		handler    http.HandlerFunc
		err        error
		expectedCA *CAResponse
	}

	run := func(t *testing.T, tc testCase) {
		svr := httptest.NewServer(tc.handler)
		defer svr.Close()

		config := &cfg.NCMConfig{
			NCMServer: svr.URL,
			Username:  "ncm-user",
			Password:  "ncm-user-password",
		}

		c, _ := NewClient(config, testr.TestLogger{})
		ca, err := c.GetCA("random-path")

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedCA != nil && !reflect.DeepEqual(tc.expectedCA, ca) {
			t.Errorf("%s failed; got %+v; want %+v", tc.name, ca, tc.expectedCA)
		}
	}

	testCases := []testCase{
		{
			name: "Successfully get CA from NCM API",
			handler: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(crt1)
				}),
			err:        nil,
			expectedCA: &crt1,
		},
		{
			name: "NCM API returned internal server error",
			handler: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					apiError := APIError{
						Message:       "Internal Server Error",
						Status:        500,
						StatusMessage: "Internal Server Error",
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(apiError)
				}),
			err:        errors.New("500"),
			expectedCA: nil,
		},
		{
			name: "Unmarshalling json error",
			handler: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					resp := map[string]string{
						"status": "500",
					}
					jsonResp, _ := json.Marshal(resp)

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write(jsonResp)
				}),
			err:        errors.New("cannot unmarshal json"),
			expectedCA: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestSendCSR(t *testing.T) {
	type testCase struct {
		name string
	}
}

func TestCheckCSRStatus(t *testing.T) {
	type testCase struct {
		name string
	}
}

func TestDownloadCertificate(t *testing.T) {
	type testCase struct {
		name string
	}
}

func TestDownloadCertificateInPEM(t *testing.T) {
	type testCase struct {
		name string
	}
}

func TestRenewCertificate(t *testing.T) {
	type testCase struct {
		name string
	}
}
