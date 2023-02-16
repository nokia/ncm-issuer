package ncmapi

import (
	"bytes"
	testr "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"testing"
)

func TestNewClientCreation(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *NCMConfig
		expectedClient *Client
		expectedError  error
	}{
		{
			name: "invalid NCM EXTERNAL API URL",
			cfg: &NCMConfig{
				NCMServer: "https://malformed url.com:80",
			},
			expectedClient: nil,
			expectedError:  &ClientError{},
		},
		{
			name: "invalid 2nd NCM EXTERNAL API URL",
			cfg: &NCMConfig{
				NCMServer:  "https://working-url.com:3000",
				NCMServer2: "https://malformed url.com:-17",
			},
			expectedClient: nil,
			expectedError:  &ClientError{},
		},
		{
			name: "invalid key pair",
			cfg: &NCMConfig{
				NCMServer:          "https://working-url.com:3000",
				NCMServer2:         "https://working-url2.com:3000",
				CACert:             "CACert",
				Key:                "Key",
				Cert:               "Cert",
				InsecureSkipVerify: false,
				MTLS:               true,
			},
			expectedClient: nil,
			expectedError:  &ClientError{},
		},
		{
			name: "proper client creation",
			cfg: &NCMConfig{
				Username:           "user",
				UsrPassword:        "password",
				NCMServer:          "https://working-url.com:3000",
				NCMServer2:         "",
				CACert:             "CACert",
				Key:                "Key",
				Cert:               "Cert",
				InsecureSkipVerify: true,
				MTLS:               false,
			},
			expectedClient: &Client{},
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		log := testr.TestLogger{T: t}
		client, err := NewClient(tt.cfg, log)
		assert.IsType(t, tt.expectedClient, client, "%s failed", tt.name)
		assert.IsType(t, tt.expectedError, err, "%s failed", tt.name)
	}
}

func TestResponseValidation(t *testing.T) {
	tests := []struct {
		name          string
		resp          *http.Response
		expectedError error
	}{
		{
			name: "not valid response",
			resp: &http.Response{
				StatusCode: 400,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"message": "", "status": 400, "statusMessage": "Bad Request"}`))),
			},
			expectedError: &APIError{},
		},
		{
			name: "valid response",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"random": "field"}`))),
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		log := testr.TestLogger{T: t}
		client, _ := NewClient(&NCMConfig{
			Username:           "user",
			UsrPassword:        "password",
			NCMServer:          "https://working-url.com:3000",
			NCMServer2:         "",
			CACert:             "CACert",
			Key:                "Key",
			Cert:               "Cert",
			InsecureSkipVerify: true,
			MTLS:               false,
		}, log)
		_, err := client.validateResponse(tt.resp)
		assert.IsType(t, tt.expectedError, err, "%s failed", tt.name)
	}
}
