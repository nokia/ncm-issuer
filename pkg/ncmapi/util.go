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

package ncmapi

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	// maxCertHrefLength bounds the accepted length of an NCM href taken from untrusted storage.
	maxCertHrefLength = 2048

	// maxCertHrefSegmentLength bounds the accepted length of a single path segment of such an href.
	maxCertHrefSegmentLength = 256

	// minCertHrefSegments requires a collection segment followed by an identifier, for example /certificates/<id>.
	minCertHrefSegments = 2
)

// certHrefSegment matches one path segment of an NCM resource href. It deliberately
// excludes the separators and wildcards that would let a rewritten href address a
// different endpoint.
var certHrefSegment = regexp.MustCompile(`^[A-Za-z0-9._~+=:@-]+$`)

func GetPathFromCertHref(certHref string) (string, error) {
	parsedURL, err := url.Parse(certHref)
	if err != nil {
		return "", fmt.Errorf("cannot parsed given href: %s", certHref)
	}
	return parsedURL.Path, nil
}

// ValidateCertHref returns the resource path of an NCM href that came from untrusted
// storage, rejecting anything that is not a plain absolute resource path. It does not
// pin a particular collection name because the NCM API base path differs between
// deployments, so callers must still confirm that the referenced resource belongs to
// them.
func ValidateCertHref(certHref string) (string, error) {
	href := strings.TrimSpace(certHref)
	if href == "" {
		return "", errors.New("href is empty")
	}

	if len(href) > maxCertHrefLength {
		return "", fmt.Errorf("href is longer than the allowed %d characters", maxCertHrefLength)
	}

	parsedURL, err := url.Parse(href)
	if err != nil {
		return "", fmt.Errorf("href is not a valid URL: %s", href)
	}

	if parsedURL.RawQuery != "" || parsedURL.ForceQuery || parsedURL.Fragment != "" || parsedURL.User != nil {
		return "", errors.New("href must not carry a query, a fragment or user information")
	}

	path := strings.TrimSuffix(parsedURL.Path, "/")
	if !strings.HasPrefix(path, "/") {
		return "", errors.New("href must contain an absolute resource path")
	}

	segments := strings.Split(path, "/")[1:]
	if len(segments) < minCertHrefSegments {
		return "", fmt.Errorf("href path must have at least %d segments", minCertHrefSegments)
	}

	for _, segment := range segments {
		switch {
		case segment == "":
			return "", errors.New("href path must not contain empty segments")
		case segment == "." || segment == "..":
			return "", errors.New("href path must not contain relative segments")
		case len(segment) > maxCertHrefSegmentLength:
			return "", fmt.Errorf("href path segment is longer than the allowed %d characters", maxCertHrefSegmentLength)
		case !certHrefSegment.MatchString(segment):
			return "", fmt.Errorf("href path segment %q contains unsupported characters", segment)
		}
	}

	return path, nil
}
