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
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/nokia/ncm-issuer/pkg/cfg"
	ncmutil "github.com/nokia/ncm-issuer/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CAsPath   = "/v1/cas"
	CSRPath   = "/v1/requests"
	healthy   = "healthy"
	unhealthy = "unhealthy"

	creationErrorReason  = "cannot create new API client"
	unmarshalErrorReason = "cannot unmarshal json"
)

// ServerURL is used to store NCM API url and health status.
type ServerURL struct {
	url    string
	health string
	mu     sync.RWMutex
}

func NewServerURL(url string) *ServerURL {
	return &ServerURL{url: url, health: healthy}
}

func (s *ServerURL) isHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.health == healthy
}

func (s *ServerURL) setHealthStatus(isHealthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if isHealthy {
		s.health = healthy
		return
	}
	s.health = unhealthy
}

// Client is a client used to communicate with the NCM API.
type Client struct {
	// mainAPI is a ServerURL which stores the url to NCM API
	// and its healthiness.
	mainAPI *ServerURL

	// backupAPI is a ServerURL which stores the url to secondary
	// NCM API in case of the lack of connection to the main
	// one and its healthiness (can be empty).
	backupAPI *ServerURL

	// stopChecking is used to stop checking the health of NCM APIs.
	stopChecking chan bool

	// user is a user used for authentication to NCM API.
	user string

	// password is a password used for authentication to NCM API.
	password string

	// useProfileIDForRenew determines whether the profile ID should be used
	// during a certificate renewal operation
	useProfileIDForRenew bool

	client *http.Client
	log    logr.Logger
}

type ClientError struct {
	Reason       string
	ErrorMessage error
}

func (c *ClientError) Error() string {
	return fmt.Sprintf("NCM API Client Error reason: %s, err: %v", c.Reason, c.ErrorMessage)
}

type CAsResponse struct {
	TotalCount int          `json:"totalCount"`
	Href       string       `json:"href"`
	CAList     []CAResponse `json:"cas"`
}

type CAResponse struct {
	Href         string            `json:"href"`
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Status       string            `json:"status"`
	Type         string            `json:"type,omitempty"`
	Certificates map[string]string `json:"certificates"`
}

type CSRResponse struct {
	Href              string `json:"href"`
	Issuer            string `json:"issuer"`
	Certificate       string `json:"certificate"`
	CertificateBase64 string `json:"certificateBase64"`
}

type CSRStatusResponse struct {
	Href        string `json:"href"`
	Issuer      string `json:"issuer"`
	Certificate string `json:"certificate"`
	Status      string `json:"status"`
}

type CertificateDownloadResponse struct {
	Href              string       `json:"href"`
	Request           string       `json:"request"`
	IssuerCA          string       `json:"issuerCa"`
	IssuedTime        *metav1.Time `json:"issuedTime,omitempty"`
	Type              string       `json:"type"`
	Status            string       `json:"status"`
	CertificateBase64 string       `json:"certificateBase64"`
}

type RenewCertificateResponse struct {
	Result      string `json:"result"`
	Request     string `json:"request,omitempty"`
	Certificate string `json:"certificate"`
}

type APIError struct {
	Message       string `json:"message,omitempty"`
	Status        int    `json:"status"`
	StatusMessage string `json:"statusMessage"`
}

func (a *APIError) Error() string {
	return fmt.Sprintf("NCM API Error status: %d, message: %s, statusMessage: %s", a.Status, a.Message, a.StatusMessage)
}

// NewClient creates a new client used to perform requests to
// the NCM API.
func NewClient(cfg *cfg.NCMConfig, log logr.Logger) (*Client, error) {
	if _, err := url.Parse(cfg.MainAPI); err != nil {
		return nil, &ClientError{Reason: creationErrorReason, ErrorMessage: err}
	}

	var backupAPI *ServerURL
	if cfg.BackupAPI != "" {
		if _, err := url.Parse(cfg.BackupAPI); err != nil {
			return nil, &ClientError{Reason: creationErrorReason, ErrorMessage: err}
		}
		backupAPI = NewServerURL(cfg.BackupAPI)
	}

	client, err := configureHTTPClient(cfg)
	if err != nil {
		return nil, &ClientError{Reason: creationErrorReason, ErrorMessage: err}
	}

	c := &Client{
		mainAPI:              NewServerURL(cfg.MainAPI),
		backupAPI:            backupAPI,
		stopChecking:         make(chan bool),
		user:                 cfg.Username,
		password:             cfg.Password,
		useProfileIDForRenew: cfg.UseProfileIDForRenew,
		client:               client,
		log:                  log,
	}

	c.StartHealthChecker(cfg.HealthCheckerInterval)
	return c, nil
}

// configureHTTPClient configures http.Client used for connection
// to NCM API according to NCM config.
func configureHTTPClient(cfg *cfg.NCMConfig) (*http.Client, error) {
	if !strings.HasPrefix(cfg.MainAPI, "https") {
		client := &http.Client{
			Timeout: cfg.HTTPClientTimeout,
		}
		return client, nil
	}

	var tlsConfig *tls.Config

	if cfg.InsecureSkipVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		CACertPool := x509.NewCertPool()
		CACertPool.AppendCertsFromPEM([]byte(cfg.CACert))

		if cfg.MTLS {
			// Loads the key pair for client certificate from PEM data in memory
			clientCert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
			if err != nil {
				return nil, err
			}
			tlsConfig = &tls.Config{
				RootCAs:      CACertPool,
				Certificates: []tls.Certificate{clientCert},
			}
		} else {
			tlsConfig = &tls.Config{
				RootCAs: CACertPool,
			}
		}
	}

	// Creates an HTTPS client and supply it with created CA pool
	// (and client CA if mTLS is enabled)
	client := &http.Client{
		Timeout: cfg.HTTPClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return client, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en_US")
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	parsedURL, _ := url.Parse(c.mainAPI.url)
	parsedURL.Path = path

	req, err := http.NewRequest(method, parsedURL.String(), body)
	if err != nil {
		return nil, &ClientError{Reason: "cannot create new request", ErrorMessage: err}
	}
	c.setHeaders(req)
	c.log.V(2).Info("Created a new HTTP request", "method", req.Method, "path", path, "bytes", req.ContentLength)
	return req, nil
}

func (c *Client) validateResponse(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	c.log.V(2).Info("Validating response from NCM API", "bytes", len(body))
	if err != nil {
		return nil, &ClientError{Reason: "cannot read response body", ErrorMessage: err}
	}

	if status := resp.StatusCode; status >= 200 && status < 300 {
		return body, nil
	}

	apiError := APIError{}
	err = json.Unmarshal(body, &apiError)
	if err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	if err = resp.Body.Close(); err != nil {
		return nil, &ClientError{Reason: "cannot close response body", ErrorMessage: err}
	}
	return nil, &apiError
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	if c.mainAPI.isHealthy() {
		resp, err := c.client.Do(req)
		if err != nil {
			c.log.Error(err, "Main NCM API seems not responding", "url", c.mainAPI.url)
			c.mainAPI.setHealthStatus(false)
			return nil, &ClientError{Reason: "not reachable NCM API", ErrorMessage: err}
		}
		return resp, nil
	} else if c.backupAPI != nil && c.backupAPI.isHealthy() {
		parsedURL, _ := url.Parse(c.backupAPI.url)
		req.URL.Host = parsedURL.Host

		resp, err := c.client.Do(req)
		if err != nil {
			c.log.Error(err, "Backup NCM API seems not responding", "url", c.backupAPI.url)
			c.backupAPI.setHealthStatus(false)
			return nil, &ClientError{Reason: "not reachable NCM API", ErrorMessage: err}
		}
		return resp, nil
	}
	return nil, &ClientError{Reason: "not reachable NCM APIs", ErrorMessage: errors.New("neither main NCM API nor backup NCM API are healthy")}
}

func (c *Client) StartHealthChecker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	c.log.V(1).Info("Starting health status checker")
	go func() {
		for {
			select {
			case <-c.stopChecking:
				ticker.Stop()
				return
			case <-ticker.C:
				c.mainAPI.setHealthStatus(
					c.isAPIHealthy(c.mainAPI.url))
				if c.backupAPI != nil {
					c.backupAPI.setHealthStatus(
						c.isAPIHealthy(c.backupAPI.url))
				}
			}
		}
	}()
}

// isAPIHealthy sends request for CAs to determine whether
// NCM API is responding or not.
func (c *Client) isAPIHealthy(apiUrl string) bool {
	parsedURL, _ := url.Parse(apiUrl)
	req, _ := http.NewRequest(http.MethodGet, parsedURL.String(), strings.NewReader(url.Values{}.Encode()))
	c.setHeaders(req)
	resp, err := c.client.Do(req)
	return err == nil && (resp.StatusCode < 500 || resp.StatusCode >= 600)
}

func (c *Client) StopHealthChecker() {
	c.log.V(1).Info("Stopping health status checker")
	close(c.stopChecking)
}

func (c *Client) GetCAs() (*CAsResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, CAsPath, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	body, err := c.validateResponse(resp)
	if err != nil {
		return nil, err
	}

	cas := CAsResponse{}
	err = json.Unmarshal(body, &cas)
	if err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	return &cas, nil
}

func (c *Client) GetCA(path string) (*CAResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, path, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	body, err := c.validateResponse(resp)
	if err != nil {
		return nil, err
	}

	ca := CAResponse{}
	err = json.Unmarshal(body, &ca)
	if err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	return &ca, nil
}

func (c *Client) SendCSR(pem []byte, CA *CAResponse, duration *metav1.Duration, profileID string) (*CSRResponse, error) {
	filePath, err := ncmutil.WritePEMToTempFile(pem)
	c.log.V(2).Info("Wrote certificate to temp PEM file", "path", filePath)
	if err != nil {
		return nil, &ClientError{Reason: "cannot write PEM to file", ErrorMessage: err}
	}
	defer func() {
		if removeErr := os.Remove(filePath); removeErr != nil {
			c.log.V(1).Info("Failed to remove temporary CSR file", "path", filePath, "error", removeErr)
		}
	}()

	certDuration := cmapi.DefaultCertificateDuration
	if duration != nil {
		certDuration = duration.Duration
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(certDuration)

	params := map[string]string{
		"ca":        CA.Href,
		"notBefore": notBefore.Format(time.RFC3339),
		"notAfter":  notAfter.Format(time.RFC3339),
	}

	if profileID != "" {
		params["profileId"] = profileID
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, &ClientError{Reason: "cannot open file", ErrorMessage: err}
	}
	defer func() {
		err = file.Close()
	}()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("pkcs10", filepath.Base(filePath))
	if err != nil {
		return nil, &ClientError{Reason: "cannot create new form-data header", ErrorMessage: err}
	}

	_, _ = io.Copy(part, file)

	for k, v := range params {
		_ = writer.WriteField(k, v)
	}

	err = writer.Close()
	if err != nil {
		return nil, &ClientError{Reason: "cannot close writer", ErrorMessage: err}
	}

	req, err := c.newRequest(http.MethodPost, CSRPath, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	respBody, err := c.validateResponse(resp)
	if err != nil {
		return nil, err
	}

	csr := CSRResponse{}
	err = json.Unmarshal(respBody, &csr)
	if err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	return &csr, err
}

func (c *Client) CheckCSRStatus(path string) (*CSRStatusResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, path, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	body, err := c.validateResponse(resp)
	if err != nil {
		return nil, err
	}

	csrStatus := CSRStatusResponse{}
	err = json.Unmarshal(body, &csrStatus)
	if err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	return &csrStatus, nil
}

func (c *Client) DownloadCertificate(path string) (*CertificateDownloadResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, path, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	body, err := c.validateResponse(resp)
	if err != nil {
		return nil, err
	}

	crt := CertificateDownloadResponse{}
	err = json.Unmarshal(body, &crt)
	if err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	return &crt, nil
}

func (c *Client) DownloadCertificateInPEM(path string) ([]byte, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, path, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/x-pem-file")
	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	body, err := c.validateResponse(resp)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (c *Client) RenewCertificate(path string, duration *metav1.Duration, profileID string) (*RenewCertificateResponse, error) {
	certDuration := cmapi.DefaultCertificateDuration
	if duration != nil {
		certDuration = duration.Duration
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(certDuration)

	newData := map[string]string{
		"notBefore": notBefore.Format(time.RFC3339Nano),
		"notAfter":  notAfter.Format(time.RFC3339Nano),
	}

	if profileID != "" && c.useProfileIDForRenew {
		newData["profileId"] = profileID
	}

	jsonData, _ := json.Marshal(&newData)
	req, err := c.newRequest(http.MethodPost, path+"/update", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	body, err := c.validateResponse(resp)
	if err != nil {
		return nil, err
	}

	renewedCrt := RenewCertificateResponse{}
	err = json.Unmarshal(body, &renewedCrt)
	if err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	return &renewedCrt, nil
}
