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

package controllers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os"
	"strings"
	"time"
)

// const URL
const (
	findCaURL        = "/v1/cas"
	sendCSRequestURL = "/v1/requests"
)

type CasType struct {
	TotalCount int          `json:"totalCount"`
	Href       string       `json:"href"`
	CasoneList []CasOneType `json:"cas"`
}

type CasOneType struct {
	Href         string            `json:"href"`
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Status       string            `json:"status"`
	Type         string            `json:"type,omitempty"`
	Certificates map[string]string `json:"certificates"`
}

type CsrRespType struct {
	Href              string `json:"href"`
	Issuer            string `json:"issuer"`
	Certificate       string `json:"certificate"`
	CertificateBase64 string `json:"certificateBase64"`
}

type CsrRequestStatusRespType struct {
	Href        string `json:"href"`
	Issuer      string `json:"issuer"`
	Certificate string `json:"certificate"`
	Status      string `json:"status"`
}

type CertificateDownloadRespType struct {
	Href              string       `json:"href"`
	Request           string       `json:"request"`
	IssuerCa          string       `json:"issuerCa"`
	IssuedTime        *metav1.Time `json:"issuedTime,omitempty"`
	Type              string       `json:"type"`
	Status            string       `json:"status"`
	CertificateBase64 string       `json:"certificateBase64"`
}

type renewCertificateRespType struct {
	Result      string `json:"result"`
	Request     string `json:"request,omitempty"`
	Certificate string `json:"certificate"`
}

// newUUID generates a random UUID according to RFC 4122
func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// write pem to temp file (dirprefix is dir prefix)
func writePemToTempFile(dirprefix string, perm []byte) (string, error) {
	myuuid, err := newUUID()
	if err != nil {
		return "", err
	}

	// path := "/tmp/ncm_new.pem"
	path := dirprefix + myuuid + ".pem"

	// write CSRPEM into csrfile
	csrfile, err := os.Create(path)
	if err != nil {
		// return nil, err, "no such file"
		return path, err
	}
	_, err = csrfile.Write(perm)
	if err != nil {
		// return nil, err, "err to write file"
		return path, err
	}
	csrfile.Sync()
	csrfile.Close()

	return path, err
}

// find and get cas list: root CA and bcmtncm CA
func findCa(ncmConfigOne *NcmConfig, log logr.Logger) (bool, error, CasType) {
	var err error

	casinfo := CasType{}
	result := CasType{}

	req, err := makeHttpNewRequest("GET", ncmConfigOne.NcmSERVER+findCaURL, ncmConfigOne)
	if err != nil {
		log.V(1).Info("http.NewRequest POST err=", err)
		return false, err, result
	}

	response, err := doHttpRequest(req, ncmConfigOne)
	if err != nil {
		log.Error(err, "failed to doHttpRequest in find CA")
		return false, err, result
	}

	defer response.Body.Close()

	body, err := getGoodResponseBody(response, log)
	if err != nil || len(body) == 0 {
		return false, fmt.Errorf("failed response in find CA"), result
	}

	err = json.Unmarshal(body, &casinfo)
	if err != nil {
		log.V(1).Info("json.Unmarshal =", string(body), err)
		return false, err, result
	}

	result = casinfo
	return false, nil, result
}
func findOneCa(downloadCaURL string, ncmConfigOne *NcmConfig, log logr.Logger) (bool, error, CasOneType) {
	var err error

	casinfo := CasOneType{}
	result := CasOneType{}

	req, err := makeHttpNewRequest("GET", downloadCaURL, ncmConfigOne)
	if err != nil {
		log.V(1).Info("http.NewRequest POST err=", err)
		return false, err, result
	}

	response, err := doHttpRequest(req, ncmConfigOne)
	if err != nil {
		log.Error(err, "failed to doHttpRequest in find CA")
		return false, err, result
	}

	defer response.Body.Close()

	body, err := getGoodResponseBody(response, log)
	if err != nil || len(body) == 0 {
		return false, fmt.Errorf("failed response in find CA"), result
	}

	err = json.Unmarshal(body, &casinfo)
	if err != nil {
		log.V(1).Info("json.Unmarshal =", string(body), err)
		return false, err, result
	}

	result = casinfo
	return false, nil, result
}

func sendCSRRequest(pem []byte, cas1 CasOneType, ncmConfigOne *NcmConfig, log logr.Logger, profileId string) (bool, error, CsrRespType) {
	var err error
	result := CsrRespType{}

	path, err := writePemToTempFile("/tmp/ncm", pem)
	if err != nil {
		return false, err, result
	}

	paramName := "pkcs10"
	extraParams := map[string]string{
		"ca": cas1.Href,
	}

	if profileId != "" {
		extraParams["profileId"] = profileId
	}

	req, err := newPostRequestWithFile(ncmConfigOne.NcmSERVER+sendCSRequestURL, extraParams, paramName, path)
	if err != nil {
		log.V(1).Info("http.NewRequest POST err=", err)
		return false, err, result
	}

	req.SetBasicAuth(ncmConfigOne.Username, ncmConfigOne.UsrPassword)

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en_US")

	// remove the temp pem file
	err = os.Remove(path)
	if err != nil {
		// return nil, err, "no such file"
		return false, err, result
	}

	response, err := doHttpRequest(req, ncmConfigOne)
	if err != nil {
		log.Error(err, "failed to doHttpRequest in sendCSRRequest")
		return false, err, result
	}

	defer response.Body.Close()

	body, err := getGoodResponseBody(response, log)
	if err != nil || len(body) == 0 {
		return false, fmt.Errorf("failed response in sendCSRRequest"), result
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		log.V(1).Info("json.Unmarshal body =", string(body), err)
		return false, err, result
	}

	return false, nil, result
}

func checkCsrRequestStatus(checkCSRrequestStatusURL string, ncmConfigOne *NcmConfig, log logr.Logger) (bool, error, CsrRequestStatusRespType) {
	var err error
	result := CsrRequestStatusRespType{}

	req, err := makeHttpNewRequest("GET", checkCSRrequestStatusURL, ncmConfigOne)
	if err != nil {
		log.V(1).Info("http.NewRequest POST err=", err)
		return false, err, result
	}

	response, err := doHttpRequest(req, ncmConfigOne)
	if err != nil {
		log.Error(err, "failed to doHttpRequest in checkCsrRequestStatus")
		return false, err, result
	}

	defer response.Body.Close()

	body, err := getGoodResponseBody(response, log)
	if err != nil || len(body) == 0 {
		return false, fmt.Errorf("failed response in checkCsrRequestStatus"), result
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		log.V(1).Info("json.Unmarshal body =", string(body), err)
		return false, err, result
	}

	return false, nil, result
}

func downloadCertificate(downloadCertificateURL string, ncmConfigOne *NcmConfig, log logr.Logger) (bool, error, CertificateDownloadRespType) {
	var err error
	result := CertificateDownloadRespType{}

	req, err := makeHttpNewRequest("GET", downloadCertificateURL, ncmConfigOne)
	if err != nil {
		log.V(1).Info("http.NewRequest POST err=", err)
		return false, err, result
	}

	response, err := doHttpRequest(req, ncmConfigOne)
	if err != nil {
		log.Error(err, "failed to doHttpRequest in downloadCertificate")
		return false, err, result
	}
	defer response.Body.Close()

	body, err := getGoodResponseBody(response, log)
	if err != nil || len(body) == 0 {
		return false, fmt.Errorf("failed response in downloadCertificate"), result
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		log.V(1).Info("json.Unmarshal body =", string(body), err)
		return false, err, result
	}

	return false, nil, result

}

func downloadCertificateInPEM(downloadCertificateURL string, ncmConfigOne *NcmConfig, log logr.Logger) (bool, error, []byte) {
	var err error
	var result []byte

	req, err := makeHttpNewRequest("GET", downloadCertificateURL, ncmConfigOne)
	if err != nil {
		log.V(1).Info("http.NewRequest POST err=", err)
		return false, err, result
	}

	req.Header.Set("Accept", "application/x-pem-file")

	response, err := doHttpRequest(req, ncmConfigOne)
	if err != nil {
		log.Error(err, "failed to doHttpRequest in downloadCertificateInPEM")
		return false, err, result
	}

	defer response.Body.Close()

	body, err := getGoodResponseBody(response, log)
	if err != nil || len(body) == 0 {
		return false, fmt.Errorf("failed response in downloadCertificateInPEM"), result
	}

	result = body

	return false, nil, result
}

// Update/renew a certificate of 'cert', renewCertificateURL is url to update
func renewCertificate(certDuration metav1.Duration, renewCertificateURL string, profileID string, ncmConfigOne *NcmConfig, log logr.Logger) (bool, error, renewCertificateRespType) {
	var err error
	result := renewCertificateRespType{}
	newData := make(map[string]string)

	notBefore := time.Now()
	notAfter := notBefore.Add(certDuration.Duration)

	newData["notBefore"] = notBefore.Format(time.RFC3339Nano)
	newData["notAfter"] = notAfter.Format(time.RFC3339Nano)
	if ncmConfigOne.useProfileIDForRenew == true {
		newData["profileID"] = profileID
	}

	jsonData, _ := json.Marshal(&newData)

	req, err := http.NewRequest("POST", renewCertificateURL+"/update", strings.NewReader(string(jsonData)))

	if err != nil {
		log.V(1).Info("http.NewRequest POST err=", err)
		// log.V(1).Info("http.NewRequest POST reader= jsonValue=", reader, jsonValue)
		// log.Fatal(err)
		return false, err, result
	}

	req.SetBasicAuth(ncmConfigOne.Username, ncmConfigOne.UsrPassword)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en_US")

	response, err := doHttpRequest(req, ncmConfigOne)
	if err != nil {
		log.Error(err, "failed to doHttpRequest in renewCertificate")
		return false, err, result
	}

	defer response.Body.Close()

	body, err := getGoodResponseBody(response, log)
	if err != nil || len(body) == 0 {
		return false, fmt.Errorf("failed response in renewCertificate"), result
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		log.V(1).Info("json.Unmarshal body =", string(body), err)
		return false, err, result
	}

	return false, nil, result
}
