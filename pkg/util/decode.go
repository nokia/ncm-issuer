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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// DecodePrivateKeyBytes will decode a PEM encoded private key into a crypto.Signer.
// It supports ECDSA and RSA private keys only. All other types will return err.
func DecodePrivateKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("error decoding private key PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs#8 private key: %s", err.Error())
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("error parsing pkcs#8 private key: invalid key type")
		}
		return signer, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing ecdsa private key: %s", err.Error())
		}

		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing rsa private key: %s", err.Error())
		}

		err = key.Validate()
		if err != nil {
			return nil, fmt.Errorf("rsa private key failed validation: %s", err.Error())
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unknown private key type: %s", block.Type)
	}
}

// DecodeX509CertificateChainBytes will decode a PEM encoded x509 Certificate chain.
func DecodeX509CertificateChainBytes(certBytes []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *pem.Block

	for {
		// decode the tls certificate pem
		block, certBytes = pem.Decode(certBytes)
		if block == nil {
			break
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing TLS certificate: %s", err.Error())
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("error decoding cert PEM block")
	}

	return certs, nil
}

// DecodeX509CertificateBytes will decode a PEM encoded x509 Certificate.
func DecodeX509CertificateBytes(certBytes []byte) (*x509.Certificate, error) {
	certs, err := DecodeX509CertificateChainBytes(certBytes)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

// DecodeX509CertificateRequestBytes will decode a PEM encoded x509 Certificate Request.
func DecodeX509CertificateRequestBytes(csrBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding certificate request PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}