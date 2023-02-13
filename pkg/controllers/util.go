package controllers

import (
	"fmt"
	"github.com/nokia/ncm-issuer/pkg/ncmapi"
	"github.com/nokia/ncm-issuer/pkg/pkiutil"
	"regexp"
	"strings"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

func validateCertificateRequest(cr *cmapi.CertificateRequest) error {
	if len(cr.Spec.Request) == 0 {
		return fmt.Errorf("certificate request is empty")
	}

	csr, err := pkiutil.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return fmt.Errorf("failed to decode CSR for validation: %v", err)
	}

	if len(csr.Subject.CommonName) == 0 && len(csr.IPAddresses) == 0 && len(csr.DNSNames) == 0 && len(csr.EmailAddresses) == 0 {
		return fmt.Errorf("at least one of field should be included in certificate spec: commonName, ipAddresses, dnsNames or emailAddresses")
	}

	return nil
}

func findCA(casResponse *ncmapi.CAsResponse, CAsHREF, CAsNAME string) (*ncmapi.CAResponse, bool) {
	hrefRegex := regexp.MustCompile(`[\d\w=_\-]+$`)
	for _, ca := range casResponse.CAList {
		if strings.EqualFold(ca.Status, "active") {
			if CAsHREF != "" {
				href := hrefRegex.Find([]byte(ca.Href))
				if string(href) == CAsHREF {
					return &ca, true
				}
			} else if ca.Name == CAsNAME {
				return &ca, true
			}
		}
	}
	return nil, false
}

func addCertToChain(crt, crtChain []byte, littleEndian bool) []byte {
	if littleEndian {
		return append(crt, crtChain...)
	}
	return append(crtChain, crt...)
}

func addLeafCertToChain(leafCrt, crtChain []byte, littleEndian bool) []byte {
	if littleEndian {
		return append(crtChain, leafCrt...)
	}
	return append(leafCrt, crtChain...)
}
