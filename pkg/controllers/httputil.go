/*


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

// Package controllers http utilities function
package controllers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	HTTPTimeout = 10
)

type ErrorReturn struct {
	ErrorSlug string `json:"error_slug"`
	Error     string `json:"error"`
}

type GetTokenErr struct{}

func (_ *GetTokenErr) Error() string {
	return "fail to get token"
}

// make http NewRequest
func makeHttpNewRequest(method string, uri string, ncmConfigOne *NcmConfig) (*http.Request, error) {

	data := url.Values{}

	req, err := http.NewRequest(method, uri, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ncmConfigOne.Username, ncmConfigOne.UsrPassword)

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en_US")

	return req, err
}

// configure http Client by NcmConfig
func configureHttpClient(ncmConfigOne *NcmConfig) (*http.Client, error) {

	var client *http.Client

	if strings.HasPrefix(ncmConfigOne.NcmSERVER, "https:") {
		var tlsConfig *tls.Config

		if ncmConfigOne.InsecureSkipVerify == true {
			tlsConfig = &tls.Config{InsecureSkipVerify: true}
		} else {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM([]byte(ncmConfigOne.Cacert))

			if ncmConfigOne.Mtls == true {
				// Read the key pair for client certificate
				clientcert, err := tls.LoadX509KeyPair(ncmConfigOne.Cert, ncmConfigOne.Key)
				if err != nil {
					return client, err
				}

				// Create an HTTPS client and supply the created CA pool and client CA
				tlsConfig = &tls.Config{RootCAs: caCertPool,
					Certificates: []tls.Certificate{clientcert},
				}
			} else {

				// Create an HTTPS client and supply the created CA pool
				tlsConfig = &tls.Config{RootCAs: caCertPool}
			}
		}

		transport := &http.Transport{TLSClientConfig: tlsConfig}

		client = &http.Client{
			Timeout:   HTTPTimeout * time.Second,
			Transport: transport,
		}
	} else {
		// The timeout to 10 seconds, which gives it enough time to connect and get a response.
		client = &http.Client{
			Timeout: HTTPTimeout * time.Second,
		}
	}
	return client, nil
}

// http Client Do(req)
func doHttpRequest(req *http.Request, ncmConfigOne *NcmConfig) (*http.Response, error) {

	client, err := configureHttpClient(ncmConfigOne)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return response, err
}

// Creates a new file upload http request with optional extra params
func newPostRequestWithFile(uri string, params map[string]string, paramName, path string) (*http.Request, error) {
	file, err := os.Open(path)
	if err != nil {
		// return nil, err, "no such file"
		return nil, err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, filepath.Base(path))
	if err != nil {
		// return nil, err, "error in writer.CreateFormFile"
		return nil, err
	}
	_, err = io.Copy(part, file)

	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
		// return nil, err, "error in writer.Close"
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if err != nil {
		// log.V(1).Info("http.NewRequest POST err=", err)
		// log.V(1).Info("http.NewRequest POST reader= jsonValue=", reader, jsonValue)
		// return nil, err, "http.NewRequest POST err"
		return nil, err
	}
	return req, err
}

// FailResponseInfo printout the failed response
func FailResponseInfo(response *http.Response, log logr.Logger) error {
	var p []byte
	var errorInfo ErrorReturn
	var err error

	p, err = ioutil.ReadAll(response.Body)

	if err != nil {
		log.Error(err, "failed to read response")
		return err
	}

	log.Info("Fail", "Http Response", string(p))
	err = json.Unmarshal(p, &errorInfo)

	if err != nil {
		log.Error(err, "failed to unmarshal error info")
		return err
	}
	fmt.Printf("Error_slug = '%s', Error = '%s'\n", errorInfo.ErrorSlug, errorInfo.Error)
	return nil
}

// check and print Failed resp
// if 2xx,  decode resp.body
func getGoodResponseBody(response *http.Response, log logr.Logger) ([]byte, error) {
	var result []byte

	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.V(1).Info("http Post body =", string(body), err)
			return result, err
		}

		return body, nil

	} else {
		log.V(1).Info("failed response status code")
		err := FailResponseInfo(response, log)
		return result, err
	}
}
