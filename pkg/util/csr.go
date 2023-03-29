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

package util

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// GenerateTemplate will create a x509.Certificate for the given
// CertificateRequest resource
func GenerateTemplateFromCertificateRequest(cr *cmapi.CertificateRequest) (*x509.Certificate, error) {
	block, _ := pem.Decode(cr.Spec.Request)
	if block == nil {
		return nil, fmt.Errorf("failed to decode csr from certificate request resource %s/%s",
			cr.Namespace, cr.Name)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err.Error())
	}

	certDuration := cmapi.DefaultCertificateDuration
	if cr.Spec.Duration != nil {
		certDuration = cr.Spec.Duration.Duration
	}

	return &x509.Certificate{
		Version:               csr.Version,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IsCA:                  cr.Spec.IsCA,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certDuration),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage:    keyUsage(cr.Spec.IsCA),
		DNSNames:    csr.DNSNames,
		IPAddresses: csr.IPAddresses,
		URIs:        csr.URIs,
	}, nil
}

func keyUsage(isCA bool) x509.KeyUsage {
	keyUsages := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if isCA {
		keyUsages |= x509.KeyUsageCertSign
	}

	return keyUsages
}
