/*
Copyright 2025 Nokia

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
	"strings"
	"testing"
)

func TestValidateCertHref(t *testing.T) {
	type testCase struct {
		name         string
		certHref     string
		expectedPath string
		expectsError bool
	}

	testCases := []testCase{
		{
			name:         "absolute-href-is-accepted",
			certHref:     "https://ncm-server.local/v1/certificates/L34FC3RT",
			expectedPath: "/v1/certificates/L34FC3RT",
		},
		{
			name:         "path-only-href-is-accepted",
			certHref:     "/certificates/L34FC3RT",
			expectedPath: "/certificates/L34FC3RT",
		},
		{
			name:         "trailing-slash-is-trimmed",
			certHref:     "https://ncm-server.local/v1/certificates/L34FC3RT/",
			expectedPath: "/v1/certificates/L34FC3RT",
		},
		{
			name:         "surrounding-whitespace-is-ignored",
			certHref:     "  https://ncm-server.local/v1/certificates/L34FC3RT  ",
			expectedPath: "/v1/certificates/L34FC3RT",
		},
		{
			name:         "empty-href-is-rejected",
			certHref:     "",
			expectsError: true,
		},
		{
			name:         "relative-href-is-rejected",
			certHref:     "cert-id",
			expectsError: true,
		},
		{
			name:         "traversal-is-rejected",
			certHref:     "https://ncm-server.local/v1/certificates/../../requests/S0M31D",
			expectsError: true,
		},
		{
			name:         "encoded-traversal-is-rejected",
			certHref:     "https://ncm-server.local/v1/certificates/%2e%2e/%2e%2e/requests/S0M31D",
			expectsError: true,
		},
		{
			name:         "single-segment-is-rejected",
			certHref:     "https://ncm-server.local/certificates",
			expectsError: true,
		},
		{
			name:         "empty-segment-is-rejected",
			certHref:     "https://ncm-server.local/v1//certificates/L34FC3RT",
			expectsError: true,
		},
		{
			name:         "query-is-rejected",
			certHref:     "https://ncm-server.local/v1/certificates/L34FC3RT?force=true",
			expectsError: true,
		},
		{
			name:         "fragment-is-rejected",
			certHref:     "https://ncm-server.local/v1/certificates/L34FC3RT#frag",
			expectsError: true,
		},
		{
			name:         "user-information-is-rejected",
			certHref:     "https://attacker@ncm-server.local/v1/certificates/L34FC3RT",
			expectsError: true,
		},
		{
			name:         "overlong-href-is-rejected",
			certHref:     "https://ncm-server.local/v1/certificates/" + strings.Repeat("a", maxCertHrefLength),
			expectsError: true,
		},
		{
			name:         "overlong-segment-is-rejected",
			certHref:     "https://ncm-server.local/v1/certificates/" + strings.Repeat("a", maxCertHrefSegmentLength+1),
			expectsError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path, err := ValidateCertHref(tc.certHref)

			if tc.expectsError {
				if err == nil {
					t.Fatalf("%s failed; expected an error; got path %q", tc.name, path)
				}
				return
			}

			if err != nil {
				t.Fatalf("%s failed; unexpected error: %v", tc.name, err)
			}

			if path != tc.expectedPath {
				t.Fatalf("%s failed; got path %q; want %q", tc.name, path, tc.expectedPath)
			}
		})
	}
}
