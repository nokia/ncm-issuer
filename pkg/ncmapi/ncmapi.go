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
	"strings"
	"sync"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/nokia/ncm-issuer/pkg/cfg"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CAsPath   = "/v1/cas"
	CSRPath   = "/v1/requests"
	healthy   = "healthy"
	unhealthy = "unhealthy"

	creationErrorReason  = "cannot create new API client"
	unmarshalErrorReason = "cannot unmarshal json"

	// maxResponseBodySize caps how many bytes are read from an NCM API response body,
	// protecting the controller from memory exhaustion if the API (or an on-path attacker
	// when server verification is disabled) returns an oversized body.
	maxResponseBodySize = 8 << 20
)

// ServerURL is used to store NCM API url and health status.
type ServerURL struct {
	url     string
	health  string
	lastErr error
	mu      sync.RWMutex
}

func NewServerURL(url string) *ServerURL {
	return &ServerURL{url: url, health: healthy}
}

func (s *ServerURL) isHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.health == healthy
}

// setHealthStatus updates the cached health status and records the underlying probe error when unhealthy.
func (s *ServerURL) setHealthStatus(isHealthy bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if isHealthy {
		s.health = healthy
		s.lastErr = nil
		return
	}
	s.health = unhealthy
	s.lastErr = err
}

// lastError returns the most recent probe error recorded for the NCM API.
func (s *ServerURL) lastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
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

// isHTTPS reports whether the given NCM API URL uses the HTTPS scheme.
func isHTTPS(rawURL string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(rawURL)), "https")
}

// configureHTTPClient configures http.Client used for connection
// to NCM API according to NCM config.
func configureHTTPClient(cfg *cfg.NCMConfig) (*http.Client, error) {
	// The main and backup NCM API share a single client, so the TLS trust
	// configuration (CA pinning, mTLS client cert) and any explicit
	// InsecureSkipVerify must be built whenever either endpoint uses HTTPS,
	// not only when the main API does.
	if !isHTTPS(cfg.MainAPI) && !isHTTPS(cfg.BackupAPI) {
		client := &http.Client{
			Timeout: cfg.HTTPClientTimeout,
		}
		return client, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Server verification is enabled by default. When a CA bundle is supplied it
	// is used as the trust anchor, otherwise RootCAs stays nil so the system trust
	// store is used. Verification is only skipped when explicitly opted in.
	switch {
	case cfg.InsecureSkipVerify:
		tlsConfig.InsecureSkipVerify = true
	case cfg.CACert != "":
		CACertPool := x509.NewCertPool()
		if !CACertPool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("failed to parse CA certificate bundle from TLS secret")
		}
		tlsConfig.RootCAs = CACertPool
	}

	// The client certificate is presented whenever mTLS material is available,
	// independently of the server verification decision.
	if cfg.MTLS {
		clientCert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	// Creates an HTTPS client and supply it with created CA pool
	// (and client CA if mTLS is enabled).
	//
	// We clone the default transport so we keep Go's sane defaults
	// (timeouts, connection pooling) and proxy support via
	// HTTP_PROXY / HTTPS_PROXY / NO_PROXY
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected default HTTP transport type")
	}
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = tlsConfig
	client := &http.Client{
		Timeout:   cfg.HTTPClientTimeout,
		Transport: transport,
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
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	c.log.V(2).Info("Validating response from NCM API", "bytes", len(body))
	if err != nil {
		return nil, &ClientError{Reason: "cannot read response body", ErrorMessage: err}
	}
	if len(body) > maxResponseBodySize {
		return nil, &ClientError{Reason: "response body too large", ErrorMessage: fmt.Errorf("NCM API response exceeded the maximum allowed size of %d bytes", maxResponseBodySize)}
	}

	if status := resp.StatusCode; status >= 200 && status < 300 {
		return body, nil
	}

	apiError := APIError{}
	err = json.Unmarshal(body, &apiError)
	if err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	return nil, &apiError
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	if c.mainAPI.isHealthy() {
		resp, err := c.client.Do(req)
		if err != nil {
			c.log.Error(err, "Main NCM API seems not responding", "url", c.mainAPI.url)
			c.mainAPI.setHealthStatus(false, err)
			return nil, &ClientError{Reason: "not reachable NCM API", ErrorMessage: err}
		}
		return resp, nil
	} else if c.backupAPI != nil && c.backupAPI.isHealthy() {
		parsedURL, _ := url.Parse(c.backupAPI.url)
		req.URL.Scheme = parsedURL.Scheme
		req.URL.Host = parsedURL.Host
		if parsedURL.Path != "" {
			req.URL.Path = parsedURL.Path + req.URL.Path
		}

		resp, err := c.client.Do(req)
		if err != nil {
			c.log.Error(err, "Backup NCM API seems not responding", "url", c.backupAPI.url)
			c.backupAPI.setHealthStatus(false, err)
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
				c.refreshHealth()
			}
		}
	}()
}

// CheckHealth performs a synchronous probe of the main NCM API and the backup
// NCM API (when configured), updates their cached health status and returns an
// error when no API is healthy. Intended to be used as a startup readiness gate
// before signaling that a dependent component is Ready.
func (c *Client) CheckHealth() error {
	c.refreshHealth()
	if c.mainAPI.isHealthy() {
		return nil
	}
	if c.backupAPI != nil && c.backupAPI.isHealthy() {
		return nil
	}
	return &ClientError{
		Reason:       "not reachable NCM APIs",
		ErrorMessage: c.healthCheckError(),
	}
}

// healthCheckError describes why no NCM API is healthy, including the underlying probe cause for each configured API.
func (c *Client) healthCheckError() error {
	msg := "neither main NCM API nor backup NCM API are healthy"
	if mainErr := c.mainAPI.lastError(); mainErr != nil {
		msg = fmt.Sprintf("%s: main API: %v", msg, mainErr)
	}
	if c.backupAPI != nil {
		if backupErr := c.backupAPI.lastError(); backupErr != nil {
			msg = fmt.Sprintf("%s; backup API: %v", msg, backupErr)
		}
	}
	return errors.New(msg)
}

// refreshHealth probes every configured NCM API once and updates the cached
// health status accordingly.
func (c *Client) refreshHealth() {
	mainHealthy, mainErr := c.isAPIHealthy(c.mainAPI.url)
	c.mainAPI.setHealthStatus(mainHealthy, mainErr)
	if c.backupAPI != nil {
		backupHealthy, backupErr := c.isAPIHealthy(c.backupAPI.url)
		c.backupAPI.setHealthStatus(backupHealthy, backupErr)
	}
}

// isAPIHealthy probes the NCM API by issuing an authenticated GET against the
// CAs endpoint and returns whether the response was 2xx together with the
// underlying failure cause when it was not.
func (c *Client) isAPIHealthy(apiURL string) (bool, error) {
	parsedURL, err := url.Parse(apiURL)
	if err != nil {
		return false, err
	}
	parsedURL.Path = strings.TrimRight(parsedURL.Path, "/") + CAsPath
	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return false, err
	}
	c.setHeaders(req)
	resp, err := c.client.Do(req)
	if err != nil {
		c.log.V(1).Info("NCM API health probe failed", "url", parsedURL.String(), "error", err.Error())
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}
	c.log.V(1).Info("NCM API health probe returned non-2xx", "url", parsedURL.String(), "status", resp.StatusCode)
	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func (c *Client) StopHealthChecker() {
	c.log.V(1).Info("Stopping health status checker")
	close(c.stopChecking)
}

// doGetJSON performs an authenticated GET against the given NCM API path and decodes the JSON body into T.
func doGetJSON[T any](c *Client, path string) (*T, error) {
	req, err := c.newRequest(http.MethodGet, path, strings.NewReader(""))
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

	result := new(T)
	if err := json.Unmarshal(body, result); err != nil {
		return nil, &ClientError{Reason: unmarshalErrorReason, ErrorMessage: err}
	}
	return result, nil
}

func (c *Client) GetCAs() (*CAsResponse, error) {
	return doGetJSON[CAsResponse](c, CAsPath)
}

func (c *Client) GetCA(path string) (*CAResponse, error) {
	return doGetJSON[CAResponse](c, path)
}

// SendCSR submits the PEM-encoded CSR to NCM as a multipart upload without touching the filesystem.
func (c *Client) SendCSR(pem []byte, ca *CAResponse, duration *metav1.Duration, profileID string) (*CSRResponse, error) {
	certDuration := cmapi.DefaultCertificateDuration
	if duration != nil {
		certDuration = duration.Duration
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(certDuration)

	params := map[string]string{
		"ca":        ca.Href,
		"notBefore": notBefore.Format(time.RFC3339),
		"notAfter":  notAfter.Format(time.RFC3339),
	}

	if profileID != "" {
		params["profileId"] = profileID
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("pkcs10", "csr.pem")
	if err != nil {
		return nil, &ClientError{Reason: "cannot create new form-data header", ErrorMessage: err}
	}

	if _, err = part.Write(pem); err != nil {
		return nil, &ClientError{Reason: "cannot write PEM to form-data part", ErrorMessage: err}
	}

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
	return doGetJSON[CSRStatusResponse](c, path)
}

func (c *Client) DownloadCertificate(path string) (*CertificateDownloadResponse, error) {
	return doGetJSON[CertificateDownloadResponse](c, path)
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
