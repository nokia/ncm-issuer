package ncmapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	DefaultHTTPTimeout = 10
	CAsURL             = "/v1/cas"
	CSRURL             = "/v1/requests"
)

// NCMConfig is a config set up with secret and used for NCM API Client configuration
type NCMConfig struct {
	Username    string
	UsrPassword string
	NCMServer   string
	NCMServer2  string

	// CAsName is a CAs for bcmtncm
	CAsName string

	// CAsHREF is a HREF for bcmtncm
	CAsHREF string

	// ReenrollmentOnRenew determines whether during renewal certificate
	// should be re-enrolled instead of renewed
	ReenrollmentOnRenew bool

	UseProfileIDForRenew bool

	// InstaCA is a NCM root CA
	InstaCA string

	// LittleEndianPem determines
	LittleEndianPem bool // bigEndian or littleEndian: bE Cert -> Issuers; lE Issuers -> Cert

	// NoRoot determines whether issuing CA certificate should be included
	// in ca.crt instead of root CA certificate
	NoRoot bool

	// ChainInSigner determines whether certificate chain should be included in ca.crt
	// (intermediate certificates + issuing CA certificate + root CA certificate)
	ChainInSigner bool

	// OnlyEECert determines whether only end-entity certificate should be included
	// in tls.crt
	OnlyEECert bool

	// CACert is a TLS CA certificate
	CACert string

	// Key is a TLS client key
	Key string

	// Cert is a TLS client certificate
	Cert string

	// InsecureSkipVerify determines whether SSL certificate verification between client
	// instance and NCM EXTERNAL API should be enabled
	InsecureSkipVerify bool

	// MTLS determines whether mTLS should be enabled
	MTLS bool
}

// NCMConfigKey is a structure used to separate different configurations for
// different namespaces
type NCMConfigKey struct {
	Namespace string
	Name      string
}

// Client is a client used to communicate with the NCM EXTERNAL API
type Client struct {
	// NCMServer is a main NCM EXTERNAL API server address
	NCMServer string

	// NCMServer2 is a secondary NCM EXTERNAL API server address
	// in case of the lack of connection to the main one (can be empty)
	NCMServer2 string

	// user is a user used for authentication to NCM EXTERNAL API
	user string

	// password is a password used for authentication to NCM EXTERNAL API
	password string

	// allowRetry determines whether, in the case of lack of the connection
	// to the main server (no response within a certain time period
	// or 5XX status code), there is an address of a second server to which
	// client can send the same request
	allowRetry bool

	// userProfileIDForRenew determines whether the profile ID should be used
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
	return fmt.Sprintf("NCM API Client Error reason=%s err=%v", c.Reason, c.ErrorMessage)
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
	return fmt.Sprintf("NCM EXTERNAL API Error status=%d, message=%s, statusMessage=%s", a.Status, a.Message, a.StatusMessage)
}

// NewClient creates a new client used to perform requests to
// the NCM EXTERNAL API
func NewClient(cfg *NCMConfig, log logr.Logger) (*Client, error) {
	NCMServerURL, err := url.Parse(cfg.NCMServer)
	if err != nil {
		return nil, &ClientError{Reason: "cannot create new API client", ErrorMessage: err}
	}

	NCMServer2URL, err := url.Parse(cfg.NCMServer2)
	if err != nil {
		return nil, &ClientError{Reason: "cannot create new API client", ErrorMessage: err}
	}

	client, err := configureHTTPClient(cfg)
	if err != nil {
		return nil, &ClientError{Reason: "cannot create new API client", ErrorMessage: err}
	}

	c := &Client{
		NCMServer:            NCMServerURL.String(),
		NCMServer2:           NCMServer2URL.String(),
		allowRetry:           cfg.NCMServer2 != "",
		user:                 cfg.Username,
		password:             cfg.UsrPassword,
		useProfileIDForRenew: cfg.UseProfileIDForRenew,
		client:               client,
		log:                  log,
	}

	return c, nil
}

// configureHTTPClient configures http.Client used for connection
// to NCM EXTERNAL API according to NCM config
func configureHTTPClient(cfg *NCMConfig) (*http.Client, error) {
	if !strings.HasPrefix(cfg.NCMServer, "https") {
		client := &http.Client{
			Timeout: DefaultHTTPTimeout * time.Second,
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
			// Reads the key pair for client certificate
			clientCert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
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
		Timeout: DefaultHTTPTimeout * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return client, nil
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	NCMServerURL, _ := url.Parse(c.NCMServer)
	NCMServerURL.Path = path

	req, err := http.NewRequest(method, NCMServerURL.String(), body)
	if err != nil {
		return nil, &ClientError{Reason: "cannot create new request", ErrorMessage: err}
	}

	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en_US")

	return req, nil
}

func (c *Client) retryRequest(req *http.Request) (*http.Response, error) {
	c.log.Info("retrying request to secondary NCM EXTERNAL API", "serverURL", c.NCMServer2)
	NCMServer2URL, _ := url.Parse(c.NCMServer2)
	req.URL.Host = NCMServer2URL.Host

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, &ClientError{Reason: "cannot perform request", ErrorMessage: err}
	}
	c.log.Info("received response from secondary NCM EXTERNAL API", "serverURL", c.NCMServer2, "status", resp.StatusCode)

	return resp, nil
}

func (c *Client) validateResponse(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &ClientError{Reason: "cannot read response body", ErrorMessage: err}
	}

	defer resp.Body.Close()

	if status := resp.StatusCode; status >= 200 && status < 300 {
		return body, nil
	}

	apiError := APIError{}
	err = json.Unmarshal(body, &apiError)
	if err != nil {
		return nil, &ClientError{Reason: "cannot unmarshal json", ErrorMessage: err}
	}

	return nil, &apiError
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		c.log.Info("main NCM EXTERNAL API seems not responding", "serverURL", c.NCMServer, "err", err)
		if c.allowRetry {
			resp, err = c.retryRequest(req)
			if err != nil {
				return nil, err
			}
			return resp, err
		}
		return nil, err
	}

	if c.allowRetry && resp.StatusCode >= 500 && resp.StatusCode < 600 {
		c.log.Info("main NCM EXTERNAL API returned server error status code", "serverURL", c.NCMServer, "status", resp.StatusCode)
		resp, err = c.retryRequest(req)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	return resp, nil
}

func (c *Client) GetCAs() (*CAsResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, CAsURL, strings.NewReader(params.Encode()))
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
		return nil, &ClientError{Reason: "cannot unmarshal json", ErrorMessage: err}
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
		return nil, &ClientError{Reason: "cannot unmarshal json", ErrorMessage: err}
	}

	return &ca, nil
}

func (c *Client) SendCSR(pem []byte, CA *CAResponse, profileId string) (*CSRResponse, error) {
	filePath, err := WritePemToTempFile("/tmp/ncm", pem)
	if err != nil {
		return nil, &ClientError{Reason: "cannot write PEM to file", ErrorMessage: err}
	}

	params := map[string]string{
		"ca": CA.Href,
	}

	if profileId != "" {
		params["profileId"] = profileId
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, &ClientError{Reason: "cannot open file", ErrorMessage: err}
	}

	defer file.Close()

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

	req, err := c.newRequest(http.MethodPost, CSRURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	err = os.Remove(filePath)
	if err != nil {
		return nil, &ClientError{Reason: "cannot remove file", ErrorMessage: err}
	}

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
		return nil, &ClientError{Reason: "cannot unmarshal json", ErrorMessage: err}
	}

	return &csr, nil
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
		return nil, &ClientError{Reason: "cannot unmarshal json", ErrorMessage: err}
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
		return nil, &ClientError{Reason: "cannot unmarshal json", ErrorMessage: err}
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

func (c *Client) RenewCertificate(path string, certDuration metav1.Duration, profileId string) (*RenewCertificateResponse, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(certDuration.Duration)

	newData := map[string]string{
		"notBefore": notBefore.Format(time.RFC3339Nano),
		"notAfter":  notAfter.Format(time.RFC3339Nano),
	}

	if profileId != "" && c.useProfileIDForRenew {
		newData["profileId"] = profileId
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
		return nil, &ClientError{Reason: "cannot unmarshal json", ErrorMessage: err}
	}

	return &renewedCrt, nil
}
