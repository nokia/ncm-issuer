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
	"github.com/nokia/ncm-issuer/pkg/controllers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	HTTPTimeout = 10
	CAsURL      = "/v1/cas"
	CSRURL      = "/v1/requests"
)

type Client struct {
	// Main NCM EXTERNAL API server address
	ncmServer string

	// Secondary NCM EXTERNAL API server address in case of the lack of connection
	// to the main one (can be empty)
	ncmServer2 string

	// User used for authentication to NCM EXTERNAL API
	user string

	// Password used for authentication to NCM EXTERNAL API
	password string

	// Determines whether, in the case of lack of the connection to the main server (no response within
	// a certain time period), there is an address of a second server to which client can send the
	// same request
	allowRetry bool

	// Determines whether the profile ID should be used during a certificate renewal operation
	useProfileIDforRenew bool

	HTTPClient *http.Client
	log        logr.Logger
}

type ClientError struct {
	Type    string
	Message error
}

func (c *ClientError) Error() string {
	return fmt.Sprintf("NCM API Client error type=%s error=%v", c.Type, c.Message)
}

type CAsResponse struct {
	TotalCount int          `json:"totalCount"`
	Href       string       `json:"href"`
	CAsList    []CAResponse `json:"cas"`
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
	Slug         string `json:"error_slug"`
	ErrorMessage string `json:"error"`
}

func (a *APIError) Error() string {
	return fmt.Sprintf("NCM EXTERNAL API Error slug=%s error=%s", a.Slug, a.ErrorMessage)
}

// Creates a new client used to perform requests to the NCM EXTERNAL API
func NewClient(ncmConfig *controllers.NcmConfig, log logr.Logger) (*Client, error) {
	HTTPClient, err := configureHTTPClient(ncmConfig)

	if err != nil {
		return nil, &ClientError{Type: "client creation error", Message: err}
	}

	c := &Client{
		ncmServer:            ncmConfig.NcmSERVER,
		ncmServer2:           ncmConfig.NcmSERVER2,
		allowRetry:           ncmConfig.NcmSERVER2 != "",
		user:                 ncmConfig.Username,
		password:             ncmConfig.UsrPassword,
		useProfileIDforRenew: ncmConfig.UseProfileIDForRenew,
		HTTPClient:           HTTPClient,
		log:                  log,
	}

	return c, nil
}

// Configures http.Client used for connection to NCM EXTERNAL API according to NCM config
func configureHTTPClient(ncmConfig *controllers.NcmConfig) (*http.Client, error) {
	if !strings.HasPrefix(ncmConfig.NcmSERVER, "https") {
		HTTPClient := &http.Client{
			Timeout: HTTPTimeout * time.Second,
		}

		return HTTPClient, nil
	}

	var tlsConfig *tls.Config

	if ncmConfig.InsecureSkipVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		CACertPool := x509.NewCertPool()
		CACertPool.AppendCertsFromPEM([]byte(ncmConfig.Cacert))

		if ncmConfig.Mtls {
			// Reads the key pair for client certificate
			clientCert, err := tls.LoadX509KeyPair(ncmConfig.Cert, ncmConfig.Key)
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

	// Creates an HTTPS client and supply it with created CA pool (and client CA if mTLS is enabled)
	HTTPClient := &http.Client{
		Timeout: HTTPTimeout * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return HTTPClient, nil
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	ncmServerURL, err := url.Parse(c.ncmServer)
	if err != nil {
		return nil, &ClientError{Type: "URL parsing error", Message: err}
	}

	ncmServerURL.Path = path

	req, err := http.NewRequest(method, ncmServerURL.String(), body)
	if err != nil {
		return nil, &ClientError{Type: "http.NewRequest creation error", Message: err}
	}

	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en_US")

	return req, nil
}

func (c *Client) retryRequest(req *http.Request) (*http.Response, error) {
	c.log.V(1).Info("retrying request to the second NCM EXTERNAL API")

	ncmServer2URL, err := url.Parse(c.ncmServer2)
	if err != nil {
		return nil, &ClientError{Type: "URL parsing error", Message: err}
	}

	req.URL.Host = ncmServer2URL.Host
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, &ClientError{Type: "http.Client.Do error", Message: err}
	}

	return resp, nil
}

func (c *Client) validateResponse(resp *http.Response) ([]byte, error) {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, &ClientError{Type: "response body read error", Message: err}
		}

		return body, nil

	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &ClientError{Type: "response body read error", Message: err}
	}

	apiError := APIError{}
	err = json.Unmarshal(body, &apiError)
	if err != nil {
		return nil, &ClientError{Type: "json unmarshal error", Message: err}
	}

	return nil, &apiError
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := c.HTTPClient.Do(req)
	if err != nil && os.IsTimeout(err) && c.allowRetry {
		c.log.V(1).Info("connection timeout exceeded while connecting to the main NCM EXTERNAL API")

		resp, err := c.retryRequest(req)
		if err != nil {
			return nil, err
		}

		return resp, nil

	} else if err != nil {
		return nil, &ClientError{Type: "http.Client.Do error", Message: err}
	}

	return resp, nil
}

func (c *Client) GetCAs() (CAsResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, CAsURL, strings.NewReader(params.Encode()))
	if err != nil {
		return CAsResponse{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return CAsResponse{}, err
	}

	defer resp.Body.Close()

	body, err := c.validateResponse(resp)
	if err != nil {
		return CAsResponse{}, err
	}

	cas := CAsResponse{}
	err = json.Unmarshal(body, &cas)
	if err != nil {
		return CAsResponse{}, &ClientError{Type: "json unmarshal error", Message: err}
	}

	return cas, nil

}

func (c *Client) GetCA(path string) (CAResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, CAsURL+path, strings.NewReader(params.Encode()))
	if err != nil {
		return CAResponse{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return CAResponse{}, err
	}

	defer resp.Body.Close()

	body, err := c.validateResponse(resp)
	if err != nil {
		return CAResponse{}, err
	}

	ca := CAResponse{}
	err = json.Unmarshal(body, &ca)
	if err != nil {
		return CAResponse{}, &ClientError{Type: "json unmarshal error", Message: err}
	}

	return ca, nil
}

func (c *Client) SendCSR(pem []byte, CA CAResponse, profileId string) (CSRResponse, error) {
	filePath, err := writePemToTempFile("/tmp/ncm", pem)
	if err != nil {
		return CSRResponse{}, &ClientError{Type: "writing file error", Message: err}
	}

	file, err := os.Open(filePath)
	if err != nil {
		return CSRResponse{}, &ClientError{Type: "opening file error", Message: err}
	}

	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("pkcs10", filepath.Base(filePath))
	if err != nil {
		return CSRResponse{}, &ClientError{Type: "writer error", Message: err}
	}

	params := map[string]string{
		"ca": CA.Href,
	}

	if profileId != "" {
		params["profileId"] = profileId
	}

	for k, v := range params {
		_ = writer.WriteField(k, v)
	}

	_, _ = io.Copy(part, file)

	err = writer.Close()
	if err != nil {
		return CSRResponse{}, &ClientError{Type: "writer error", Message: err}
	}

	req, err := c.newRequest(http.MethodPost, CSRURL, body)
	if err != nil {
		return CSRResponse{}, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	err = os.Remove(filePath)
	if err != nil {
		return CSRResponse{}, &ClientError{Type: "removing file error", Message: err}
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return CSRResponse{}, err
	}

	defer resp.Body.Close()

	respBody, err := c.validateResponse(resp)
	if err != nil {
		return CSRResponse{}, err
	}

	csr := CSRResponse{}
	err = json.Unmarshal(respBody, &csr)
	if err != nil {
		return CSRResponse{}, &ClientError{Type: "json unmarshal error", Message: err}
	}

	return csr, nil
}

func (c *Client) CheckCSRStatus(path string) (CSRStatusResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, path, strings.NewReader(params.Encode()))
	if err != nil {
		return CSRStatusResponse{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return CSRStatusResponse{}, err
	}

	defer resp.Body.Close()

	body, err := c.validateResponse(resp)
	if err != nil {
		return CSRStatusResponse{}, err
	}

	csrStatus := CSRStatusResponse{}
	err = json.Unmarshal(body, &csrStatus)
	if err != nil {
		return CSRStatusResponse{}, &ClientError{Type: "json unmarshal error", Message: err}
	}

	return csrStatus, nil
}

func (c *Client) DownloadCertificate(path string) (CertificateDownloadResponse, error) {
	params := url.Values{}
	req, err := c.newRequest(http.MethodGet, path, strings.NewReader(params.Encode()))
	if err != nil {
		return CertificateDownloadResponse{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return CertificateDownloadResponse{}, err
	}

	defer resp.Body.Close()

	body, err := c.validateResponse(resp)
	if err != nil {
		return CertificateDownloadResponse{}, err
	}

	certificate := CertificateDownloadResponse{}
	err = json.Unmarshal(body, &certificate)
	if err != nil {
		return CertificateDownloadResponse{}, &ClientError{Type: "json unmarshal error", Message: err}
	}

	return certificate, nil
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

	defer resp.Body.Close()

	body, err := c.validateResponse(resp)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func (c *Client) RenewCertificate(path string, certDuration metav1.Duration, profileId string) (RenewCertificateResponse, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(certDuration.Duration)

	newData := map[string]string{
		"notBefore": notBefore.Format(time.RFC3339Nano),
		"notAfter":  notAfter.Format(time.RFC3339Nano),
	}

	if profileId != "" && c.useProfileIDforRenew {
		newData["profileId"] = profileId
	}

	jsonData, _ := json.Marshal(&newData)
	req, err := c.newRequest(http.MethodPost, path+"/update", strings.NewReader(string(jsonData)))
	if err != nil {
		return RenewCertificateResponse{}, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return RenewCertificateResponse{}, err
	}

	defer resp.Body.Close()

	body, err := c.validateResponse(resp)
	if err != nil {
		return RenewCertificateResponse{}, err
	}

	renewedCertificate := RenewCertificateResponse{}
	err = json.Unmarshal(body, &renewedCertificate)
	if err != nil {
		return RenewCertificateResponse{}, &ClientError{Type: "json unmarshal error", Message: err}
	}

	return renewedCertificate, nil
}
