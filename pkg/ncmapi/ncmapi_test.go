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
		name string
		cfg  *NCMConfig
	}{
		{
			name: "invalidNCMServerURL",
			cfg: &NCMConfig{
				NcmSERVER: "https://malformed url.com:80",
			},
		},
		{
			name: "invalidNCMServer2URL",
			cfg: &NCMConfig{
				NcmSERVER:  "https://working-url.com:3000",
				NcmSERVER2: "https://malformed url.com:-17",
			},
		},
		{
			name: "invalidKeyPair",
			cfg: &NCMConfig{
				NcmSERVER:          "https://working-url.com:3000",
				NcmSERVER2:         "https://working-url2.com:3000",
				CACert:             "CACert",
				Key:                "Key",
				Cert:               "Cert",
				InsecureSkipVerify: false,
				MTLS:               true,
			},
		},
		{
			name: "properClientCreation",
			cfg: &NCMConfig{
				Username:           "user",
				UsrPassword:        "password",
				NcmSERVER:          "https://working-url.com:3000",
				NcmSERVER2:         "",
				CACert:             "CACert",
				Key:                "Key",
				Cert:               "Cert",
				InsecureSkipVerify: true,
				MTLS:               false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := testr.TestLogger{T: t}
			if client, err := NewClient(tt.cfg, log); err != nil {
				assert.ErrorIs(t, err, err.(*ClientError))
			} else {
				assert.IsType(t, &Client{}, client)
			}
		})
	}
}

func TestResponseValidation(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
	}{
		{
			name: "notValidResponse",
			resp: &http.Response{
				StatusCode: 400,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"message": "", "status": 400, "statusMessage": "Bad Request"}`))),
			},
		},
		{
			name: "validResponse",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"random": "field"}`))),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := testr.TestLogger{T: t}
			client, _ := NewClient(&NCMConfig{
				Username:           "user",
				UsrPassword:        "password",
				NcmSERVER:          "https://working-url.com:3000",
				NcmSERVER2:         "",
				CACert:             "CACert",
				Key:                "Key",
				Cert:               "Cert",
				InsecureSkipVerify: true,
				MTLS:               false,
			}, log)

			if body, err := client.validateResponse(tt.resp); err != nil {
				assert.ErrorIs(t, err, err.(*APIError))
			} else {
				assert.IsType(t, []byte("random-field"), body)
			}
		})
	}
}
