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

package cfg

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	ncmutil "github.com/nokia/ncm-issuer/pkg/util"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	DefaultHTTPTimeout           = 10 * time.Second
	DefaultHealthCheckerInterval = time.Minute
)

// NCMConfig stores the configuration which defines the behaviour of ncm-issuer.
type NCMConfig struct {
	// MainAPI is a main NCM API server address.
	MainAPI string

	// BackupAPI is a secondary NCM API server address
	// in case of the lack of connection to the main one (can be empty).
	BackupAPI string

	// Username is a username used for authentication to NCM API.
	Username string

	// Password is a password used for authentication to NCM API.
	Password string

	// CAName is a name for an existing CA in NCM API, which will
	// be used to issue certificates.
	CAName string

	// CAID is a unique identifier for an existing CA in NCM API,
	// which will be used to issue certificates.
	CAID string

	// ReenrollmentOnRenew determines whether during renewal certificate
	// should be re-enrolled instead of renewed.
	ReenrollmentOnRenew bool

	// ProfileID is an entity profile ID
	ProfileID string

	// UseProfileIDForRenew determines whether the profile ID should be used
	// during a certificate renewal operation
	UseProfileIDForRenew bool

	// LittleEndian determines bytes order.
	LittleEndian bool

	// NoRoot determines whether singing CA certificate should be included
	// in ca.crt instead of root CA certificate.
	NoRoot bool

	// ChainInSigner determines whether certificate chain should be included in ca.crt
	// (intermediate certificates + singing CA certificate + root CA certificate).
	ChainInSigner bool

	// OnlyEECert determines whether only end-entity certificate should be included
	// in tls.crt.
	OnlyEECert bool

	// HTTPClientTimeout is a maximum amount of time that the
	// HTTP client will wait for a response from NCM API before
	// aborting the request.
	HTTPClientTimeout time.Duration

	// HealthCheckerInterval is the time interval between each
	// NCM API health check.
	HealthCheckerInterval time.Duration

	// AuthNamespacedName is a NamespacedName that points to a secret
	// which contains authentication data needed for making requests to NCM API.
	AuthNamespacedName types.NamespacedName

	// TLSNamespacedName is a NamespacedName that points to a secret
	// which contains TLS configuration for the NCM API
	TLSNamespacedName types.NamespacedName

	// CACert is a TLS CA certificate.
	CACert string

	// Key is a TLS client key.
	Key string

	// Cert is a TLS client certificate.
	Cert string

	// InsecureSkipVerify determines whether SSL certificate verification between client
	// instance and NCM API should be enabled.
	InsecureSkipVerify bool

	// MTLS determines whether mTLS should be enabled.
	MTLS bool
}

func Initialise(issuerSpec *ncmv1.IssuerSpec) *NCMConfig {
	config := &NCMConfig{
		Username:              "",
		Password:              "",
		CAName:                issuerSpec.CAName,
		CAID:                  issuerSpec.CAID,
		ReenrollmentOnRenew:   issuerSpec.ReenrollmentOnRenew,
		ProfileID:             issuerSpec.ProfileID,
		UseProfileIDForRenew:  issuerSpec.UseProfileIDForRenew,
		LittleEndian:          issuerSpec.LittleEndian,
		NoRoot:                issuerSpec.NoRoot,
		ChainInSigner:         issuerSpec.ChainInSigner,
		OnlyEECert:            issuerSpec.OnlyEECert,
		HTTPClientTimeout:     DefaultHTTPTimeout,
		HealthCheckerInterval: DefaultHealthCheckerInterval,
		AuthNamespacedName:    types.NamespacedName{},
		TLSNamespacedName:     types.NamespacedName{},
		CACert:                "",
		Key:                   "",
		Cert:                  "",
		InsecureSkipVerify:    true,
		MTLS:                  false,
	}

	if p := issuerSpec.Provisioner; p != nil {
		config.MainAPI = strings.TrimSuffix(p.MainAPI, "/")
		config.BackupAPI = strings.TrimSuffix(p.BackupAPI, "/")
		config.HTTPClientTimeout = time.Duration(p.HTTPClientTimeout.Nanoseconds())
		config.HealthCheckerInterval = time.Duration(p.HealthCheckerInterval.Nanoseconds())
		config.AuthNamespacedName.Namespace, config.AuthNamespacedName.Name = p.AuthRef.Namespace, p.AuthRef.Name
		if p.TLSRef != nil {
			config.TLSNamespacedName.Namespace, config.TLSNamespacedName.Name = p.TLSRef.Namespace, p.TLSRef.Name
		}
	}

	config.handleDeprecatedFields(issuerSpec)
	return config
}

func (cfg *NCMConfig) AddAuthenticationData(secret *core.Secret) {
	if username, ok := secret.Data["username"]; ok {
		cfg.Username = string(username)
	} else {
		cfg.Username = ""
	}

	if password, ok := secret.Data["usrPassword"]; ok {
		cfg.Password = string(password)
	} else {
		cfg.Password = ""
	}
}

func (cfg *NCMConfig) AddTLSData(secret *core.Secret) error {
	if CACert, ok := secret.Data["cacert"]; ok {
		cfg.CACert = string(CACert)
	} else {
		cfg.CACert = ""
	}
	cfg.InsecureSkipVerify = cfg.CACert == ""

	if key, ok := secret.Data["key"]; ok {
		keyPath, err := ncmutil.WritePEMToTempFile(key)
		if err != nil {
			return err
		}
		cfg.Key = keyPath
	} else {
		cfg.Key = ""
	}

	if cert, ok := secret.Data["cert"]; ok {
		certPath, err := ncmutil.WritePEMToTempFile(cert)
		if err != nil {
			return err
		}
		cfg.Cert = certPath
	} else {
		cfg.Cert = ""
	}
	cfg.MTLS = cfg.Key != "" && cfg.Cert != ""

	return nil
}

func (cfg *NCMConfig) InjectNamespace(namespace string) {
	if cfg.AuthNamespacedName.Namespace == "" {
		cfg.AuthNamespacedName.Namespace = namespace
	}

	if cfg.TLSNamespacedName.Name != "" && cfg.TLSNamespacedName.Namespace == "" {
		cfg.TLSNamespacedName.Namespace = namespace
	}
}

func (cfg *NCMConfig) Validate() error {
	if cfg.MainAPI == "" {
		return fmt.Errorf("incorrect NCM API data: missing main API url")
	}

	if cfg.Username == "" || cfg.Password == "" {
		return fmt.Errorf("incorrect authentication data: missing username or usrpassword")
	}

	if cfg.CAName == "" && cfg.CAID == "" {
		return fmt.Errorf("incorrect signing CA certificate data: missing CANAME or CAHREF")
	}

	if !reflect.DeepEqual(cfg.TLSNamespacedName, types.NamespacedName{}) && cfg.CACert == "" && cfg.Key == "" && cfg.Cert == "" {
		return fmt.Errorf("incorrect TLS data: missing cacert, key or cert in TLS secret")
	}

	return nil
}

func (cfg *NCMConfig) handleDeprecatedFields(issuerSpec *ncmv1.IssuerSpec) {
	if cfg.MainAPI == "" {
		cfg.MainAPI = strings.TrimSuffix(issuerSpec.NCMServer, "/")
	}

	if cfg.BackupAPI == "" {
		cfg.BackupAPI = strings.TrimSuffix(issuerSpec.NCMServer2, "/")
	}

	if cfg.CAName == "" {
		cfg.CAName = issuerSpec.CAsName
	}

	if cfg.CAID == "" {
		cfg.CAID = issuerSpec.CAsHREF
	}

	if reflect.DeepEqual(cfg.AuthNamespacedName, types.NamespacedName{}) {
		cfg.AuthNamespacedName.Namespace = issuerSpec.AuthNamespace
		cfg.AuthNamespacedName.Name = issuerSpec.AuthSecretName
	}

	if reflect.DeepEqual(cfg.TLSNamespacedName, types.NamespacedName{}) {
		cfg.TLSNamespacedName.Name = issuerSpec.TLSSecretName
	}
}
