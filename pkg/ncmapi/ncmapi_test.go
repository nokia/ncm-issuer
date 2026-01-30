/*
Copyright 2025 Nokia

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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/google/go-cmp/cmp"
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

func compareClients(c1, c2 *Client) bool {
	if c1.mainAPI.url != c2.mainAPI.url {
		return false
	}

	if c1.useProfileIDForRenew != c2.useProfileIDForRenew {
		return false
	}

	if !compareHTTPClients(c1.client, c2.client) {
		return false
	}

	return true
}

func compareHTTPClients(c1, c2 *http.Client) bool {
	if c1 == nil || c2 == nil {
		return c1 == c2
	}

	if c1.Timeout != c2.Timeout {
		return false
	}

	if c1.Transport == nil || c2.Transport == nil {
		return c1.Transport == c2.Transport
	}

	t1, ok := c1.Transport.(*http.Transport)
	if !ok {
		return false
	}
	t2, ok := c2.Transport.(*http.Transport)
	if !ok {
		return false
	}

	return compareTLSConfig(t1.TLSClientConfig, t2.TLSClientConfig)
}

func compareTLSConfig(c1, c2 *tls.Config) bool {
	if c1 == nil || c2 == nil {
		return c1 == c2
	}
	if c1.InsecureSkipVerify != c2.InsecureSkipVerify {
		return false
	}
	if (c1.RootCAs == nil) != (c2.RootCAs == nil) {
		return false
	}
	if len(c1.Certificates) != len(c2.Certificates) {
		return false
	}
	return true
}

func TestNewClientCreation(t *testing.T) {
	type testCase struct {
		name           string
		config         *cfg.NCMConfig
		err            error
		expectedClient *Client
	}

	CACertPool := x509.NewCertPool()
	CACertPool.AppendCertsFromPEM([]byte(rootCA))

	clientCert, _ := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))

	run := func(t *testing.T, tc testCase) {
		var c *Client
		var err error
		if tc.expectedClient != nil {
			c, err = NewClient(tc.config, tc.expectedClient.log)
		} else {
			c, err = NewClient(tc.config, testr.New(t))
		}

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedClient != nil && !compareClients(tc.expectedClient, c) {
			t.Fatalf("%s failed; created and expected client is not the same", tc.name)
		}
	}

	testCases := []testCase{
		{
			name: "malformed-main-ncm-api-url",
			config: &cfg.NCMConfig{
				MainAPI:               "https://ncm-server.local:-8081",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
			},
			err:            errors.New("cannot create new API client"),
			expectedClient: nil,
		},
		{
			name: "malformed-backup-ncm-api-url",
			config: &cfg.NCMConfig{
				MainAPI:               "https://ncm-server.local",
				BackupAPI:             "https://ncm-backup-server.local:-8081",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
			},
			err:            errors.New("cannot create new API client"),
			expectedClient: nil,
		},
		{
			name: "cert-and-key-for-mtls-invalid-pem",
			config: &cfg.NCMConfig{
				MainAPI:               "https://ncm-server.local",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
				CACert:                rootCA,
				Key:                   []byte("invalid-key-pem"),
				Cert:                  []byte("invalid-cert-pem"),
			},
			err:            errors.New("failed to parse"),
			expectedClient: nil,
		},
		{
			name: "ncm-client-success-insecure-connection",
			config: &cfg.NCMConfig{
				MainAPI:               "http://ncm-server.local",
				Username:              "ncm-user",
				Password:              "ncm-user-password",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
			},
			err: nil,
			expectedClient: &Client{
				mainAPI:  NewServerURL("http://ncm-server.local"),
				user:     "ncm-user",
				password: "ncm-user-password",
				client: &http.Client{
					Timeout: 10 * time.Second,
				},
				log: testr.New(t),
			},
		},
		{
			name: "ncm-client-success-insecure-skip-verify",
			config: &cfg.NCMConfig{
				MainAPI:               "https://ncm-server.local",
				Username:              "ncm-user",
				Password:              "ncm-user-password",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
				InsecureSkipVerify:    true,
			},
			err: nil,
			expectedClient: &Client{
				mainAPI:  NewServerURL("https://ncm-server.local"),
				user:     "ncm-user",
				password: "ncm-user-password",
				client: &http.Client{
					Timeout: 10 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					},
				},
				log: testr.New(t),
			},
		},
		{
			name: "ncm-client-success-tls-connection",
			config: &cfg.NCMConfig{
				MainAPI:               "https://ncm-server.local",
				Username:              "ncm-user",
				Password:              "ncm-user-password",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
				CACert:                rootCA,
			},
			err: nil,
			expectedClient: &Client{
				mainAPI:  NewServerURL("https://ncm-server.local"),
				user:     "ncm-user",
				password: "ncm-user-password",

				client: &http.Client{
					Timeout: 10 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							RootCAs: CACertPool,
						},
					},
				},
				log: testr.New(t),
			},
		},
		{
			name: "ncm-client-success-mtls-connection",
			config: &cfg.NCMConfig{
				MainAPI:               "https://ncm-server.local",
				Username:              "ncm-user",
				Password:              "ncm-user-password",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
				CACert:                rootCA,
				MTLS:                  true,
				Cert:                  []byte(certPEM),
				Key:                   []byte(keyPEM),
			},
			err: nil,
			expectedClient: &Client{
				mainAPI:  NewServerURL("https://ncm-server.local"),
				user:     "ncm-user",
				password: "ncm-user-password",
				client: &http.Client{
					Timeout: 10 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							RootCAs:      CACertPool,
							Certificates: []tls.Certificate{clientCert},
						},
					},
				},
				log: testr.New(t),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestNewRequestCreation(t *testing.T) {
	type testCase struct {
		name   string
		method string
		err    error
	}

	run := func(t *testing.T, tc testCase) {
		config := &cfg.NCMConfig{
			MainAPI:               "https://ncm-server.local",
			Username:              "ncm-user",
			Password:              "ncm-user-password",
			HTTPClientTimeout:     10 * time.Second,
			HealthCheckerInterval: time.Minute,
		}

		c, _ := NewClient(config, testr.New(t))
		params := url.Values{}
		_, err := c.newRequest(tc.method, "random-path", strings.NewReader(params.Encode()))

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}
	}

	testCases := []testCase{
		{
			name:   "new-request-invalid-method",
			method: "Konstantynopolitańczykówna",
			err:    errors.New("invalid method"),
		},
		{
			name:   "new-request-success",
			method: http.MethodGet,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

type failReader int

func (failReader) Read([]byte) (int, error) {
	return 0, errors.New("unable to read from body unexpected EOF")
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
			MainAPI:               "https://ncm-server.local",
			Username:              "ncm-user",
			Password:              "ncm-user-password",
			HTTPClientTimeout:     10 * time.Second,
			HealthCheckerInterval: time.Minute,
		}

		c, _ := NewClient(config, testr.New(t))
		body, err := c.validateResponse(tc.resp)

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedBody != nil {
			if diff := cmp.Diff(tc.expectedBody, body); diff != "" {
				t.Fatalf("%s failed; received and wanted body is not the same (-want +got)\n%s", tc.name, diff)
			}
		}
	}

	testCases := []testCase{
		{
			name: "response-validation-success-status-200",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewBuffer(
					[]byte(`{"name": "ncmCA", "status": "active"}`))),
			},
			expectedBody: []byte(`{"name": "ncmCA", "status": "active"}`),
		},
		{
			name: "response-validation-success-for-status-not-200",
			resp: &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body: io.NopCloser(bytes.NewBuffer(
					[]byte(`{"message": "Internal Server Error", "status": 500, "statusMessage": "Internal Server Error"}`))),
			},
			err: errors.New("500"),
		},
		{
			name: "unmarshalling-json-error",
			resp: &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body: io.NopCloser(bytes.NewBuffer(
					[]byte(`{"message": "Internal Server Error", "status": "500", "statusMessage": "Internal Server Error"}`))),
			},
			err: errors.New("cannot unmarshal json"),
		},
		{
			name: "read-response-body-error",
			resp: &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(failReader(0)),
			},
			err: errors.New("cannot read response body"),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestIsAPIHealthy(t *testing.T) {
	type testCase struct {
		name              string
		handler           http.HandlerFunc
		expectedIsHealthy bool
	}

	run := func(t *testing.T, tc testCase) {
		svr := httptest.NewServer(tc.handler)
		defer svr.Close()

		config := &cfg.NCMConfig{
			MainAPI:               svr.URL,
			Username:              "ncm-user",
			Password:              "ncm-user-password",
			HTTPClientTimeout:     10 * time.Second,
			HealthCheckerInterval: time.Minute,
		}

		c, _ := NewClient(config, testr.New(t))
		isHealthy := c.isAPIHealthy(c.mainAPI.url)
		if isHealthy != tc.expectedIsHealthy {
			t.Fatalf("%s failed; expected API health to be %T; got %T", tc.name, tc.expectedIsHealthy, isHealthy)
		}
	}

	testCases := []testCase{
		{
			name: "api-is-healthy",
			handler: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(cas)
				}),
			expectedIsHealthy: true,
		},
		{
			name: "api-is-not-healthy",
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
			expectedIsHealthy: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestDoRequest(t *testing.T) {
	type testCase struct {
		name             string
		handlerMainAPI   http.HandlerFunc
		handlerBackupAPI http.HandlerFunc
		isBackupAPI      bool
		err              error
	}

	run := func(t *testing.T, tc testCase) {
		svrMain := httptest.NewServer(tc.handlerMainAPI)
		defer svrMain.Close()

		var config *cfg.NCMConfig
		if tc.isBackupAPI {
			svrBackup := httptest.NewServer(tc.handlerBackupAPI)
			defer svrBackup.Close()
			config = &cfg.NCMConfig{
				MainAPI:               svrMain.URL,
				BackupAPI:             svrBackup.URL,
				Username:              "ncm-user",
				Password:              "ncm-user-password",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
			}
		} else {
			config = &cfg.NCMConfig{
				MainAPI:               svrMain.URL,
				Username:              "ncm-user",
				Password:              "ncm-user-password",
				HTTPClientTimeout:     10 * time.Second,
				HealthCheckerInterval: time.Minute,
			}
		}

		c, _ := NewClient(config, testr.New(t))
		req, _ := c.newRequest(http.MethodGet, CAsPath, strings.NewReader(url.Values{}.Encode()))
		_, err := c.doRequest(req)

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}
	}

	testCases := []testCase{
		{
			name: "main-api-is-healthy",
			handlerMainAPI: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(cas)
				}),
		},
		{
			name: "main-api-is-not-healthy",
			handlerMainAPI: http.HandlerFunc(
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
			err: errors.New("not reachable NCM API"),
		},
		{
			name: "backup-api-is-healthy",
			handlerMainAPI: http.HandlerFunc(
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
			handlerBackupAPI: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(cas)
				}),
		},
		{
			name: "none-api-is-healthy",
			handlerMainAPI: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(cas)
				}),
			handlerBackupAPI: http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(cas)
				}),
			err: errors.New("neither main NCM API nor backup NCM API are healthy"),
		},
	}

	for _, tc := range testCases {
		tc := tc
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
			MainAPI:               svr.URL,
			Username:              "ncm-user",
			Password:              "ncm-user-password",
			HTTPClientTimeout:     10 * time.Second,
			HealthCheckerInterval: time.Minute,
		}

		c, _ := NewClient(config, testr.New(t))
		cas, err := c.GetCAs()

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedCAs != nil {
			if diff := cmp.Diff(tc.expectedCAs, cas); diff != "" {
				t.Fatalf("%s failed; received and wanted CAs are not the same (-want +got)\n%s", tc.name, diff)
			}
		}
	}

	testCases := []testCase{
		{
			name: "get-cas-success",
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
			name: "get-cas-internal-server-error",
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
			name: "get-cas-unmarshalling-json-error",
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
		tc := tc
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
			MainAPI:               svr.URL,
			Username:              "ncm-user",
			Password:              "ncm-user-password",
			HTTPClientTimeout:     10 * time.Second,
			HealthCheckerInterval: time.Minute,
		}

		c, _ := NewClient(config, testr.New(t))
		ca, err := c.GetCA("random-path")

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedCA != nil {
			if diff := cmp.Diff(tc.expectedCA, ca); diff != "" {
				t.Fatalf("%s failed; received and wanted CA is not the same (-want +got)\n%s", tc.name, diff)
			}
		}
	}

	testCases := []testCase{
		{
			name: "get-ca-success",
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
			name: "get-ca-internal-server-error",
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
			name: "get-ca-unmarshalling-json-error",
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}
