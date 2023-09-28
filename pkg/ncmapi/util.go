package ncmapi

import (
	"fmt"
	"net/url"
)

func GetPathFromCertHref(certHref string) (string, error) {
	parsedURL, err := url.Parse(certHref)
	if err != nil {
		return "", fmt.Errorf("cannot parsed given href: %s", certHref)
	}
	return parsedURL.Path, nil
}
