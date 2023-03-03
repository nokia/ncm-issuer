package provisioner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nokia/ncm-issuer/pkg/ncmapi"
)

func findCA(casResponse *ncmapi.CAsResponse, CAsHref, CAsName string) (*ncmapi.CAResponse, bool) {
	hrefRegex := regexp.MustCompile(`[\d\w=_\-]+$`)
	for _, ca := range casResponse.CAList {
		if strings.EqualFold(ca.Status, "active") {
			if CAsHref != "" {
				href := hrefRegex.Find([]byte(ca.Href))
				if string(href) == CAsHref {
					return &ca, true
				}
			} else if ca.Name == CAsName {
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

func prepareCSRsMapKey(namespace, crtName string) string {
	return fmt.Sprintf("%s.%s", namespace, crtName)
}
