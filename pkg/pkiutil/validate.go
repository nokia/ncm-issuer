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

package pkiutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// PublicKeyMatchesCertificate can be used to verify the given public key
// is the correct counter-part to the given x509 Certificate.
// It will return false and no error if the public key is *not* valid for the
// given Certificate.
// It will return true if the public key *is* valid for the given Certificate.
// It will return an error if either of the passed parameters are of an
// unrecognised type (i.e. non RSA/ECDSA)
func PublicKeyMatchesCertificate(check crypto.PublicKey, crt *x509.Certificate) (bool, error) {
	switch pub := crt.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaCheck, ok := check.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		if pub.N.Cmp(rsaCheck.N) != 0 {
			return false, nil
		}
		return true, nil
	case *ecdsa.PublicKey:
		ecdsaCheck, ok := check.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		if pub.X.Cmp(ecdsaCheck.X) != 0 || pub.Y.Cmp(ecdsaCheck.Y) != 0 {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("unrecognised Certificate public key type")
	}
}

func CertificateHasKeyUsage(cert *x509.Certificate, usage x509.KeyUsage) bool {
	if cert.KeyUsage != 0 && cert.KeyUsage&usage != 0 {
		return true
	}
	return false
}
