package cfg

import (
	"reflect"
	"testing"

	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var (
	defaultProvisioner = &ncmv1.NCMProvisioner{
		MainAPI:               "https://ncm-server.local:8081",
		BackupAPI:             "https://ncm-server-backup.local:8081",
		HTTPClientTimeout:     metav1.Duration{Duration: DefaultHTTPTimeout},
		HealthCheckerInterval: metav1.Duration{Duration: DefaultHealthCheckerInterval},
		AuthRef: &core.SecretReference{
			Namespace: "ncm-ns",
			Name:      "ncm-auth-secret",
		},
		TLSRef: &core.SecretReference{
			Namespace: "ncm-tls-ns",
			Name:      "ncm-tls-secret",
		},
	}
	defaultSpecWithoutProvisioner = &ncmv1.IssuerSpec{
		CAName:               "name",
		CAID:                 "caID",
		ReenrollmentOnRenew:  false,
		ProfileID:            "profileID",
		UseProfileIDForRenew: false,
		LittleEndian:         false,
		NoRoot:               false,
		ChainInSigner:        false,
		OnlyEECert:           false,
	}

	defaultSpec = deepCopyIssuerSpecWithProvisioner(defaultSpecWithoutProvisioner)
)

func deepCopyIssuerSpecWithProvisioner(spec *ncmv1.IssuerSpec) *ncmv1.IssuerSpec {
	issuerCopy := &ncmv1.IssuerSpec{
		CAName:               spec.CAName,
		CAID:                 spec.CAID,
		ReenrollmentOnRenew:  spec.ReenrollmentOnRenew,
		ProfileID:            spec.ProfileID,
		UseProfileIDForRenew: spec.UseProfileIDForRenew,
		LittleEndian:         spec.LittleEndian,
		NoRoot:               spec.NoRoot,
		ChainInSigner:        spec.ChainInSigner,
		OnlyEECert:           spec.OnlyEECert,
	}

	issuerCopy.Provisioner = defaultProvisioner

	return issuerCopy
}
func TestInitialise(t *testing.T) {
	tests := []struct {
		name string
		spec *ncmv1.IssuerSpec
		want *NCMConfig
	}{
		{
			name: "config-without-provisioner",
			spec: defaultSpecWithoutProvisioner,
			want: &NCMConfig{
				Username:              "",
				Password:              "",
				CAName:                defaultSpec.CAName,
				CAID:                  defaultSpec.CAID,
				ReenrollmentOnRenew:   defaultSpec.ReenrollmentOnRenew,
				ProfileID:             defaultSpec.ProfileID,
				UseProfileIDForRenew:  defaultSpec.UseProfileIDForRenew,
				LittleEndian:          defaultSpec.LittleEndian,
				NoRoot:                defaultSpec.LittleEndian,
				ChainInSigner:         defaultSpec.NoRoot,
				OnlyEECert:            defaultSpec.OnlyEECert,
				HTTPClientTimeout:     DefaultHTTPTimeout,
				HealthCheckerInterval: DefaultHealthCheckerInterval,
				AuthNamespacedName:    types.NamespacedName{},
				TLSNamespacedName:     types.NamespacedName{},
				CACert:                "",
				Key:                   nil,
				Cert:                  nil,
				InsecureSkipVerify:    true,
				MTLS:                  false,
			},
		},
		{
			name: "config-with-provisioner",
			spec: defaultSpec,
			want: &NCMConfig{
				CAName:                defaultSpecWithoutProvisioner.CAName,
				CAID:                  defaultSpecWithoutProvisioner.CAID,
				ReenrollmentOnRenew:   defaultSpecWithoutProvisioner.ReenrollmentOnRenew,
				ProfileID:             defaultSpecWithoutProvisioner.ProfileID,
				UseProfileIDForRenew:  defaultSpecWithoutProvisioner.UseProfileIDForRenew,
				LittleEndian:          defaultSpecWithoutProvisioner.LittleEndian,
				NoRoot:                defaultSpecWithoutProvisioner.LittleEndian,
				ChainInSigner:         defaultSpecWithoutProvisioner.NoRoot,
				OnlyEECert:            defaultSpecWithoutProvisioner.OnlyEECert,
				HTTPClientTimeout:     DefaultHTTPTimeout,
				HealthCheckerInterval: DefaultHealthCheckerInterval,

				InsecureSkipVerify: true,
				MTLS:               false,
				MainAPI:            defaultProvisioner.MainAPI,
				BackupAPI:          defaultProvisioner.BackupAPI,
				AuthNamespacedName: types.NamespacedName{
					Namespace: "ncm-ns",
					Name:      "ncm-auth-secret",
				},
				TLSNamespacedName: types.NamespacedName{
					Namespace: "ncm-tls-ns",
					Name:      "ncm-tls-secret",
				},
			},
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Initialise(tt.spec); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Initialise() = \n%v, want \n%v", got, tt.want)
			}
		})
	}
}

func TestNCMConfigAddAuthenticationData(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *NCMConfig
		secret         *core.Secret
		expectedConfig *NCMConfig
	}{
		{
			name: "UsernameAndPasswordPresent-ShouldSetCorrectValues",
			cfg:  &NCMConfig{},
			secret: &core.Secret{
				Data: map[string][]byte{
					"username":    []byte("test-user"),
					"usrPassword": []byte("test-pass"),
				},
			},
			expectedConfig: &NCMConfig{
				Username: "test-user",
				Password: "test-pass",
			},
		},
		{
			name: "UsernameMissing-ShouldSetUsernameToEmptyString",
			cfg:  &NCMConfig{Username: "randomValueForExpectedOverride"},
			secret: &core.Secret{
				Data: map[string][]byte{
					"usrPassword": []byte("test-pass"),
				},
			},
			expectedConfig: &NCMConfig{
				Username: "",
				Password: "test-pass",
			},
		},
		{
			name: "PasswordMissing-ShouldSetPasswordToEmptyString",
			cfg:  &NCMConfig{Password: "randomValueForExpectedOverride"},
			secret: &core.Secret{
				Data: map[string][]byte{
					"username": []byte("test-user"),
				},
			},
			expectedConfig: &NCMConfig{
				Username: "test-user",
				Password: "",
			},
		},
		{
			name: "UsernameAndPasswordMissing-ShouldSetBothToEmptyStrings",
			cfg:  &NCMConfig{},
			secret: &core.Secret{
				Data: map[string][]byte{},
			},
			expectedConfig: &NCMConfig{
				Username: "",
				Password: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.AddAuthenticationData(tt.secret)

			if tt.cfg.Username != tt.expectedConfig.Username {
				t.Errorf("got username %v, expected %v", tt.cfg.Username, tt.expectedConfig.Username)
			}
			if tt.cfg.Password != tt.expectedConfig.Password {
				t.Errorf("got password %v, expected %v", tt.cfg.Password, tt.expectedConfig.Password)
			}
		})
	}
}
func TestInjectNamespace(t *testing.T) {
	tests := []struct {
		name                  string
		initialAuthNamespace  string
		initialTLSName        string
		initialTLSNamespace   string
		namespace             string
		expectedAuthNamespace string
		expectedTLSNamespace  string
	}{
		{
			name:                  "AuthNamespace empty, TLSNamespace empty",
			initialAuthNamespace:  "",
			initialTLSName:        "tls-secret",
			initialTLSNamespace:   "",
			namespace:             "default",
			expectedAuthNamespace: "default",
			expectedTLSNamespace:  "default",
		},
		{
			name:                  "AuthNamespace set, TLSNamespace empty",
			initialAuthNamespace:  "existing-ns",
			initialTLSName:        "tls-secret",
			initialTLSNamespace:   "",
			namespace:             "default",
			expectedAuthNamespace: "existing-ns", // Should not overwrite existing AuthNamespace
			expectedTLSNamespace:  "default",     // Should set the new namespace
		},
		{
			name:                  "AuthNamespace set, TLSNamespace set",
			initialAuthNamespace:  "existing-ns",
			initialTLSName:        "tls-secret",
			initialTLSNamespace:   "existing-tls-ns",
			namespace:             "default",
			expectedAuthNamespace: "existing-ns",     // Should not overwrite existing AuthNamespace
			expectedTLSNamespace:  "existing-tls-ns", // Should not overwrite existing TLSNamespace
		},
		{
			name:                  "TLSName empty, AuthNamespace set",
			initialAuthNamespace:  "existing-ns",
			initialTLSName:        "",
			initialTLSNamespace:   "",
			namespace:             "default",
			expectedAuthNamespace: "existing-ns",
			expectedTLSNamespace:  "", // No TLS name, so namespace should not be set
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &NCMConfig{
				AuthNamespacedName: types.NamespacedName{
					Namespace: tt.initialAuthNamespace,
				},
				TLSNamespacedName: types.NamespacedName{
					Name:      tt.initialTLSName,
					Namespace: tt.initialTLSNamespace,
				},
			}

			config.InjectNamespace(tt.namespace)
			if config.AuthNamespacedName.Namespace != tt.expectedAuthNamespace {
				t.Errorf("AuthNamespacedName.Namespace = %v, want %v", config.AuthNamespacedName.Namespace, tt.expectedAuthNamespace)
			}
			if config.TLSNamespacedName.Namespace != tt.expectedTLSNamespace {
				t.Errorf("TLSNamespacedName.Namespace = %v, want %v", config.TLSNamespacedName.Namespace, tt.expectedTLSNamespace)
			}
		})
	}
}

func TestNCMConfigValidate(t *testing.T) {
	tests := []struct {
		name          string
		cfg           *NCMConfig
		expectedError string
	}{
		{
			name: "MainAPIEmpty-ShouldReturnError",
			cfg: &NCMConfig{
				MainAPI:           "",
				CAID:              "valid-ca-id",
				Username:          "user",
				Password:          "pass",
				CAName:            "CAName",
				TLSNamespacedName: types.NamespacedName{},
			},
			expectedError: "Failed to validate config provided in spec: incorrect NCM API data: missing main API url",
		},
		{
			name: "CAIDInUnsupportedFormat-ShouldReturnError",
			cfg: &NCMConfig{
				MainAPI:           "https://mainapi.server",
				CAID:              "https://mainapi.server/v1/cas/someID",
				Username:          "user",
				Password:          "pass",
				CAName:            "CAName",
				TLSNamespacedName: types.NamespacedName{},
			},
			expectedError: `Failed to validate config provided in spec: incorrect caID "https://mainapi.server/v1/cas/someID". Please provide only ID of the https://ncm.domain.example/v1/cas/{ID} endpoint`,
		},
		{
			name: "MissingUsernameOrPassword-ShouldReturnError",
			cfg: &NCMConfig{
				MainAPI:           "https://mainapi.server",
				CAID:              "valid-ca-id",
				Username:          "",
				Password:          "",
				CAName:            "CAName",
				TLSNamespacedName: types.NamespacedName{},
			},
			expectedError: "Failed to validate config provided in spec: incorrect authentication data: missing username or usrpassword",
		},
		{
			name: "MissingCANameAndCAID-ShouldReturnError",
			cfg: &NCMConfig{
				MainAPI:           "https://mainapi.server",
				CAID:              "",
				Username:          "user",
				Password:          "pass",
				CAName:            "",
				TLSNamespacedName: types.NamespacedName{},
			},
			expectedError: "Failed to validate config provided in spec: incorrect signing CA certificate data: missing CANAME or CAHREF",
		},
		{
			name: "MissingCACertKeyCertInTLSSecret-ShouldReturnError",
			cfg: &NCMConfig{
				MainAPI:  "https://mainapi.server",
				CAID:     "valid-ca-id",
				Username: "user",
				Password: "pass",
				CAName:   "CAName",
				TLSNamespacedName: types.NamespacedName{
					Namespace: "auth-ns",
					Name:      "tls-secret",
				},
				CACert: "",
				Key:    nil,
				Cert:   nil,
			},
			expectedError: "Failed to validate config provided in spec: incorrect TLS data: missing cacert, key or cert in TLS secret",
		},
		{
			name: "ValidConfig-ShouldPassValidation",
			cfg: &NCMConfig{
				MainAPI:  "https://mainapi.server",
				CAID:     "valid-ca-id",
				Username: "user",
				Password: "pass",
				CAName:   "CAName",
				TLSNamespacedName: types.NamespacedName{
					Namespace: "auth-ns",
					Name:      "tls-secret",
				},
				CACert: "cacert",
				Key:    []byte("key"),
				Cert:   []byte("cert"),
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectedError != "" {
				if err == nil || err.Error() != tt.expectedError {
					t.Errorf("got error %v, expected %v", err, tt.expectedError)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, but got %v", err)
				}
			}
		})
	}
}

func TestHandleDeprecatedFields(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *NCMConfig
		issuerSpec     *ncmv1.IssuerSpec
		expectedConfig *NCMConfig
	}{
		{
			name: "MainAPI-and-BackupAPI-not-set-should-copy-from-IssuerSpec",
			cfg: &NCMConfig{
				MainAPI:            "",
				BackupAPI:          "",
				CAName:             "",
				CAID:               "",
				AuthNamespacedName: types.NamespacedName{},
				TLSNamespacedName:  types.NamespacedName{},
			},
			issuerSpec: &ncmv1.IssuerSpec{
				NCMServer:      "https://mainapi.server",
				NCMServer2:     "https://backupapi.server",
				CAsName:        "MyCAName",
				CAsHREF:        "https://my-ca-id",
				AuthNamespace:  "auth-ns",
				AuthSecretName: "auth-secret",
				TLSSecretName:  "tls-secret",
			},
			expectedConfig: &NCMConfig{
				MainAPI:   "https://mainapi.server",
				BackupAPI: "https://backupapi.server",
				CAName:    "MyCAName",
				CAID:      "https://my-ca-id",
				AuthNamespacedName: types.NamespacedName{
					Namespace: "auth-ns",
					Name:      "auth-secret",
				},
				TLSNamespacedName: types.NamespacedName{
					Name: "tls-secret",
				},
			},
		},
		{
			name: "MainAPI-and-BackupAPI-not-set-should-copy-from-IssuerSpec-backshash-trimmed",
			cfg: &NCMConfig{
				MainAPI:            "",
				BackupAPI:          "",
				CAName:             "",
				CAID:               "",
				AuthNamespacedName: types.NamespacedName{},
				TLSNamespacedName:  types.NamespacedName{},
			},
			issuerSpec: &ncmv1.IssuerSpec{
				NCMServer:      "https://mainapi.server/",
				NCMServer2:     "https://backupapi.server/",
				CAsName:        "MyCAName",
				CAsHREF:        "https://my-ca-id",
				AuthNamespace:  "auth-ns",
				AuthSecretName: "auth-secret",
				TLSSecretName:  "tls-secret",
			},
			expectedConfig: &NCMConfig{
				MainAPI:   "https://mainapi.server",
				BackupAPI: "https://backupapi.server",
				CAName:    "MyCAName",
				CAID:      "https://my-ca-id",
				AuthNamespacedName: types.NamespacedName{
					Namespace: "auth-ns",
					Name:      "auth-secret",
				},
				TLSNamespacedName: types.NamespacedName{
					Name: "tls-secret",
				},
			},
		},
		{
			name: "Fields-already-set-should-not-override",
			cfg: &NCMConfig{
				MainAPI:   "https://existing-mainapi.server",
				BackupAPI: "https://existing-backupapi.server",
				CAName:    "ExistingCAName",
				CAID:      "https://existing-ca-id",
				AuthNamespacedName: types.NamespacedName{
					Namespace: "existing-auth-ns",
					Name:      "existing-auth-secret",
				},
				TLSNamespacedName: types.NamespacedName{
					Name: "existing-tls-secret",
				},
			},
			issuerSpec: &ncmv1.IssuerSpec{
				NCMServer:      "https://mainapi.server",
				NCMServer2:     "https://backupapi.server",
				CAsName:        "MyCAName",
				CAsHREF:        "https://my-ca-id",
				AuthNamespace:  "auth-ns",
				AuthSecretName: "auth-secret",
				TLSSecretName:  "tls-secret",
			},
			expectedConfig: &NCMConfig{
				MainAPI:   "https://existing-mainapi.server",
				BackupAPI: "https://existing-backupapi.server",
				CAName:    "ExistingCAName",
				CAID:      "https://existing-ca-id",
				AuthNamespacedName: types.NamespacedName{
					Namespace: "existing-auth-ns",
					Name:      "existing-auth-secret",
				},
				TLSNamespacedName: types.NamespacedName{
					Name: "existing-tls-secret",
				},
			},
		},
		{
			name: "Partially-set-fields-should-fill-in-missing-fields-only",
			cfg: &NCMConfig{
				MainAPI:            "https://existing-mainapi.server",
				BackupAPI:          "",
				CAName:             "",
				CAID:               "https://existing-ca-id",
				AuthNamespacedName: types.NamespacedName{},
				TLSNamespacedName:  types.NamespacedName{},
			},
			issuerSpec: &ncmv1.IssuerSpec{
				NCMServer:      "https://mainapi.server",
				NCMServer2:     "https://backupapi.server",
				CAsName:        "MyCAName",
				CAsHREF:        "https://my-ca-id",
				AuthNamespace:  "auth-ns",
				AuthSecretName: "auth-secret",
				TLSSecretName:  "tls-secret",
			},
			expectedConfig: &NCMConfig{
				MainAPI:   "https://existing-mainapi.server",
				BackupAPI: "https://backupapi.server",
				CAName:    "MyCAName",
				CAID:      "https://existing-ca-id",
				AuthNamespacedName: types.NamespacedName{
					Namespace: "auth-ns",
					Name:      "auth-secret",
				},
				TLSNamespacedName: types.NamespacedName{
					Name: "tls-secret",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.handleDeprecatedFields(tt.issuerSpec)

			if !reflect.DeepEqual(tt.cfg, tt.expectedConfig) {
				t.Errorf("got %v, want %v", tt.cfg, tt.expectedConfig)
			}
		})
	}
}
