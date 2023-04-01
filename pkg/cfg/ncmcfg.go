package cfg

import (
	"fmt"
	"strings"

	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	ncmutil "github.com/nokia/ncm-issuer/pkg/util"
	core "k8s.io/api/core/v1"
)

// NCMConfig stores the configuration which defines the behaviour of ncm-issuer.
type NCMConfig struct {
	// NCMServer is a main NCM API server address.
	NCMServer string

	// NCMServer2 is a secondary NCM API server address
	// in case of the lack of connection to the main one (can be empty).
	NCMServer2 string

	// Username is a username used for authentication to NCM API.
	Username string

	// Password is a password used for authentication to NCM API.
	Password string

	// CAsName is a CA certificate name which will issue generated certificates.
	CAsName string

	// CAsHREF is a CA certificate href which will issue generated certificates.
	CAsHref string

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

	// TLSSecretName is a secret which contains TLS configuration for the NCM API
	TLSSecretName string

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
	return &NCMConfig{
		NCMServer:            strings.TrimSuffix(issuerSpec.NCMServer, "/"),
		NCMServer2:           strings.TrimSuffix(issuerSpec.NCMServer2, "/"),
		Username:             "",
		Password:             "",
		CAsName:              issuerSpec.CAsName,
		CAsHref:              issuerSpec.CAsHREF,
		ReenrollmentOnRenew:  issuerSpec.ReenrollmentOnRenew,
		ProfileID:            issuerSpec.ProfileID,
		UseProfileIDForRenew: issuerSpec.UseProfileIDForRenew,
		LittleEndian:         issuerSpec.LittleEndian,
		NoRoot:               issuerSpec.NoRoot,
		ChainInSigner:        issuerSpec.ChainInSigner,
		OnlyEECert:           issuerSpec.OnlyEECert,
		TLSSecretName:        issuerSpec.TLSSecretName,
		CACert:               "",
		Key:                  "",
		Cert:                 "",
		InsecureSkipVerify:   true,
		MTLS:                 false,
	}
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

func (cfg *NCMConfig) Validate() error {
	if cfg.NCMServer == "" {
		return fmt.Errorf("incorrect NCM API address: missing ncmSERVER address")
	}

	if cfg.Username == "" || cfg.Password == "" {
		return fmt.Errorf("incorrect authentication data: missing username or usrpassword")
	}

	if cfg.CAsName == "" && cfg.CAsHref == "" {
		return fmt.Errorf("incorrect signing CA certificate data: missing CANAME or CAHREF")
	}

	if cfg.TLSSecretName != "" && cfg.CACert == "" && cfg.Key == "" && cfg.Cert == "" {
		return fmt.Errorf("incorrect TLS data: missing cacert, key or cert in TLS secret")
	}

	return nil
}
