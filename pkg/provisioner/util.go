/*
Copyright 2023 Nokia

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

package provisioner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nokia/ncm-issuer/pkg/ncmapi"
)

func findCA(casResponse *ncmapi.CAsResponse, casHref, casName string) (*ncmapi.CAResponse, bool) {
	hrefRegex := regexp.MustCompile(`[\w=_\-]+$`)
	for _, ca := range casResponse.CAList {
		if strings.EqualFold(ca.Status, "active") {
			if casHref != "" {
				href := hrefRegex.Find([]byte(ca.Href))
				if string(href) == casHref {
					return &ca, true
				}
			} else if ca.Name == casName {
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
