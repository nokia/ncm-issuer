package cfg

import (
	"testing"
)

func TestUnsupportedCaIdPatterns(t *testing.T) {
	tests := []struct {
		input               string
		looksLikeMistake    bool
		testCaseDescription string
	}{
		{
			input:               "/v1/cas/nZ2QfzjGv0U3HmJuVxEsZQ",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-pasted"},
		{
			input:               "/v1/cas/nZ2QfzjGv0U3HmJuVxEsZQ/",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-pasted-trailing-slash",
		},
		{
			input:               "v1/cas/nZ2QfzjGv0U3HmJuVxEsZQ",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-pasted-no-initial-slash",
		},
		{
			input:               "v1/cas/nZ2QfzjGv0U3HmJuVxEsZQ/",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-pasted-no-initial-slash-trailing-slash",
		},
		{
			input:               "/v2/cas/abcdef123456",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-pasted-new-api-version-test",
		},
		{
			input:               "/v1/cas/123-456_ABC",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-pasted-different-ID",
		},
		{
			input:               "/v1/cas",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-missing-id",
		},
		{
			input:               "v1/cas/",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-missing-id-no-initial-slash",
		},
		{
			input:               "v1/cas/",
			looksLikeMistake:    true,
			testCaseDescription: "api-path-copied-from-the-ncm-ca-details-missing-id-no-initial-slas-trailing-slash",
		},
		{
			input:               "https://ncm.domain.example/v1/cas/123-456_ABC",
			looksLikeMistake:    true,
			testCaseDescription: "full-url-provided-https",
		},
		{
			input:               "http://ncm.domain.example/v1/cas/123-456_ABC",
			looksLikeMistake:    true,
			testCaseDescription: "full-url-provided-http",
		},
		{
			input:               "ncm.domain.example/v1/cas/123-456_ABC",
			looksLikeMistake:    true,
			testCaseDescription: "full-url-provided-no-protocol",
		},
		{
			input:               "https://ncm.ca/cas/123-456_ABC",
			looksLikeMistake:    true,
			testCaseDescription: "another-full-url-provided",
		},
		{
			input:               "",
			looksLikeMistake:    false,
			testCaseDescription: "empty-should-not-happen-as-this-is-mandatory-non-empty-field-in-spec",
		},
		{
			input:               "nZ2QfzjGv0U3HmJuVxEsZQ",
			looksLikeMistake:    false,
			testCaseDescription: "corrent-caID",
		},
	}

	for _, test := range tests {
		t.Run(test.testCaseDescription, func(t *testing.T) {
			result := caIDInUnsupportedFormat(test.input)
			if result != test.looksLikeMistake {
				t.Errorf("Description: %s - matchPattern(%q) = %v; looksLikeMistake %v", test.testCaseDescription, test.input, result, test.looksLikeMistake)
			}
		})
	}
}
