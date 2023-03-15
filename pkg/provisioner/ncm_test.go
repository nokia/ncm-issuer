package provisioner

import (
	"errors"
	"strings"
	"sync"
	"testing"

	testr "github.com/go-logr/logr/testing"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/nokia/ncm-issuer/pkg/cfg"
	"github.com/nokia/ncm-issuer/pkg/ncmapi"
	"github.com/nokia/ncm-issuer/test/unit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	crt1 = ncmapi.CAResponse{
		Href:   "https://ncm-server.local/cas/Mn012Se",
		Name:   "ncmCA",
		Status: "active",
		Certificates: map[string]string{
			"active": "https://ncm-servver-local/certificate/Mn012Se",
		},
	}

	crt2 = ncmapi.CAResponse{
		Href:   "https://ncm-server.local/cas/eS210nM",
		Name:   "ncmCA2",
		Status: "active",
		Certificates: map[string]string{
			"active": "https://ncm-servver-local/certificate/eS210nM",
		},
	}

	crt3 = ncmapi.CAResponse{
		Href:         "https://ncm-server.local/cas/efG312Ed",
		Name:         "ncmCA3",
		Status:       "expired",
		Certificates: map[string]string{},
	}

	CAsResponse = &ncmapi.CAsResponse{
		TotalCount: 3,
		Href:       "https://ncm-server.local/cas",
		CAList:     []ncmapi.CAResponse{crt1, crt2, crt3},
	}

	cr = cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ncm-ns",
		},
		Spec: cmapi.CertificateRequestSpec{
			Request: []byte("-----BEGIN CERTIFICATE-----\nR3Qu3St...\n-----END CERTIFICATE-----\n"),
		},
	}
)

func TestFindCA(t *testing.T) {
	type testCase struct {
		name        string
		CAsHref     string
		CAsName     string
		CAsResponse *ncmapi.CAsResponse
		isFindable  bool
		expectedCA  *ncmapi.CAResponse
	}

	run := func(t *testing.T, tc testCase) {
		_, found := findCA(tc.CAsResponse, tc.CAsHref, tc.CAsName)

		if tc.isFindable != found {
			t.Fatalf("%s failed; expected (not) to find CA certificate; got %t; want %t", tc.name, found, tc.isFindable)
		}
	}

	testCases := []testCase{
		{
			name:        "Findable by CAsName",
			CAsHref:     "",
			CAsName:     "ncmCA2",
			CAsResponse: CAsResponse,
			isFindable:  true,
			expectedCA:  &crt2,
		},
		{
			name:        "Findable by CAsHref",
			CAsHref:     "Mn012Se",
			CAsName:     "",
			CAsResponse: CAsResponse,
			isFindable:  true,
			expectedCA:  &crt1,
		},
		{
			name:        "CAsName case sensitive",
			CAsHref:     "",
			CAsName:     "NCMca2",
			CAsResponse: CAsResponse,
			isFindable:  false,
			expectedCA:  &ncmapi.CAResponse{},
		},
		{
			name:        "CAsHref case sensitive",
			CAsHref:     "mN012sE",
			CAsName:     "",
			CAsResponse: CAsResponse,
			isFindable:  false,
			expectedCA:  &ncmapi.CAResponse{},
		},
		{
			name:        "CA certificate findable but not active",
			CAsHref:     "efG312Ed",
			CAsName:     "ncmCA3",
			CAsResponse: CAsResponse,
			isFindable:  false,
			expectedCA:  &ncmapi.CAResponse{},
		},
		{
			name:        "Empty CAsName & CAsHref",
			CAsHref:     "",
			CAsName:     "",
			CAsResponse: CAsResponse,
			isFindable:  false,
			expectedCA:  &ncmapi.CAResponse{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestGetChainAndWantedCA(t *testing.T) {
	type testCase struct {
		name          string
		fakeClient    ncmapi.ExternalClient
		err           error
		expectedChain []byte
		expectedCA    []byte
	}

	run := func(t *testing.T, tc testCase) {
		p := &Provisioner{
			NCMConfig: &cfg.NCMConfig{},
			NCMClient: tc.fakeClient,
			pendingCSRs: &PendingCSRsMap{
				pendingCSRs: map[string]*PendingCSR{},
				mu:          sync.RWMutex{},
			},
			log: &testr.TestLogger{T: t},
		}

		chain, ca, err := p.getChainAndWantedCA(&crt1)

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; want %s", tc.name, err.Error(), tc.err.Error())
		}

		if string(tc.expectedCA) != string(ca) {
			t.Errorf("%s failed; got %s; want %s", tc.name, string(ca), string(tc.expectedCA))
		}

		if string(tc.expectedChain) != string(chain) {
			t.Errorf("%s failed; got %s; want %s", tc.name, string(chain), string(tc.expectedChain))
		}
	}

	testCases := []testCase{
		{
			name: "Successfully get chain & CA",
			fakeClient: unit.NewFakeClient(
				unit.SetFakeClientGetCA(nil),
				unit.SetFakeClientDownloadCertificate(nil),
				unit.SetFakeClientDownloadCertificateInPEM(nil)),
			err:           nil,
			expectedChain: []byte(""),
			expectedCA:    []byte("-----BEGIN CERTIFICATE-----\nMn012Se...\n-----END CERTIFICATE-----\n"),
		},
		{
			name: "Failed to get chain & CA (cannot download certificate)",
			fakeClient: unit.NewFakeClient(
				unit.SetFakeClientGetCA(nil),
				unit.SetFakeClientDownloadCertificate(errors.New("failed to download CA certificate")),
				unit.SetFakeClientDownloadCertificateInPEM(nil)),
			err:           errors.New("failed to download CA certificate"),
			expectedChain: []byte(""),
			expectedCA:    []byte(""),
		},
		{
			name: "Failed to get chain & CA (cannot download certificate in PEM)",
			fakeClient: unit.NewFakeClient(
				unit.SetFakeClientGetCA(nil),
				unit.SetFakeClientDownloadCertificate(nil),
				unit.SetFakeClientDownloadCertificateInPEM(errors.New("failed to download CA certificate in PEM")),
			),
			err:           errors.New("failed to download CA certificate in PEM"),
			expectedChain: []byte(""),
			expectedCA:    []byte(""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestPreparingCAAndTLS(t *testing.T) {
	type testCase struct {
		name        string
		config      *cfg.NCMConfig
		expectedCA  []byte
		expectedTLS []byte
	}

	rootCA := []byte("-----BEGIN CERTIFICATE-----\nR00TC4...\n-----END CERTIFICATE-----\n")
	interCA := []byte("-----BEGIN CERTIFICATE-----\n1NT3RC4...\n-----END CERTIFICATE-----\n")
	signingCA := []byte("-----BEGIN CERTIFICATE-----\n1SSU1NGC4...\n-----END CERTIFICATE-----\n")
	leafCert := []byte("-----BEGIN CERTIFICATE-----\nL34FC4RT...\n-----END CERTIFICATE-----\n")

	run := func(t *testing.T, tc testCase) {

		p, _ := NewProvisioner(tc.config, &testr.TestLogger{T: t})
		ca, tls := p.prepareCAAndTLS(rootCA, leafCert, func() []byte {
			if tc.config.LittleEndian {
				return append(interCA, signingCA...)
			}
			return append(signingCA, interCA...)
		}())

		if string(tc.expectedCA) != string(ca) {
			t.Errorf("%s failed; got %s; want %s", tc.name, string(ca), string(tc.expectedCA))
		}

		if string(tc.expectedTLS) != string(tls) {
			t.Errorf("%s failed; got %s; want %s", tc.name, string(tls), string(tc.expectedTLS))
		}
	}

	testCases := []testCase{
		{
			name:        "All CA and TLS manipulation options set to false",
			config:      &cfg.NCMConfig{},
			expectedCA:  rootCA,
			expectedTLS: append(leafCert, append(signingCA, interCA...)...),
		},
		{
			name: "littleEndian set to true",
			config: &cfg.NCMConfig{
				LittleEndian: true,
			},
			expectedCA:  rootCA,
			expectedTLS: append(interCA, append(signingCA, leafCert...)...),
		},
		{
			name: "chainInSigner set to true",
			config: &cfg.NCMConfig{
				ChainInSigner: true,
			},
			expectedCA:  append(signingCA, append(interCA, rootCA...)...),
			expectedTLS: append(leafCert, append(signingCA, interCA...)...),
		},
		{
			name: "littleEndian & chainInSigner set to true",
			config: &cfg.NCMConfig{
				LittleEndian:  true,
				ChainInSigner: true,
			},
			expectedCA:  append(rootCA, append(interCA, signingCA...)...),
			expectedTLS: append(interCA, append(signingCA, leafCert...)...),
		},
		{
			name: "onlyEECert set to true",
			config: &cfg.NCMConfig{
				OnlyEECert: true,
			},
			expectedCA:  rootCA,
			expectedTLS: leafCert,
		},
		{
			name: "chainInSigner & onlyEECert set to true",
			config: &cfg.NCMConfig{
				ChainInSigner: true,
				OnlyEECert:    true,
			},
			expectedCA:  append(signingCA, append(interCA, rootCA...)...),
			expectedTLS: leafCert,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}

func TestSign(t *testing.T) {
	type testCase struct {
		name        string
		cr          *cmapi.CertificateRequest
		p           *Provisioner
		err         error
		expectedCA  []byte
		expectedTLS []byte
	}

	run := func(t *testing.T, tc testCase) {
		ca, tls, _, err := tc.p.Sign(tc.cr)

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; want %s", tc.name, err.Error(), tc.err.Error())
		}

		if string(tc.expectedCA) != string(ca) {
			t.Errorf("%s failed; got %s; want %s", tc.name, string(ca), string(tc.expectedCA))
		}

		if string(tc.expectedTLS) != string(tls) {
			t.Errorf("%s failed; got %s; want %s", tc.name, string(tls), string(tc.expectedTLS))
		}
	}

	cr.Annotations = map[string]string{
		cmapi.CertificateNameKey: "ncm-certificate",
	}

	testCases := []testCase{
		{
			name: "Failed to get CAs",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, ErrFailedGetCAs),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("pending", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrFailedGetCAs,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Failed to send CSR",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(errors.New("cannot established connection")),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("pending", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         errors.New("failed to send CSR"),
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Failed to check CSR status",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("", errors.New("cannot established connection"))),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         errors.New("failed checking CSR status in NCM"),
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Approved CSR status in NCM API",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("approved", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{
						"ncm-ns.ncm-certificate": {
							href:    "https://ncm-server.local/requests/EufA12",
							checked: 1,
						},
					},
					mu: sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrCSRNotAccepted,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Pending CSR status in NCM API",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("pending", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{
						"ncm-ns.ncm-certificate": {
							href:    "https://ncm-server.local/requests/EufA12",
							checked: 1,
						},
					},
					mu: sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrCSRNotAccepted,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Pending CSR status in NCM API (pending CSR check limit exceeded)",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("pending", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{
						"ncm-ns.ncm-certificate": {
							href:    "https://ncm-server.local/requests/EufA12",
							checked: SingleCSRCheckLimit + 1,
						},
					},
					mu: sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrCSRCheckLimitExceeded,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Postponed CSR status in NCM API",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("postponed", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{
						"ncm-ns.ncm-certificate": {
							href:    "https://ncm-server.local/requests/EufA12",
							checked: 1,
						},
					},
					mu: sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrCSRRejected,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Rejected CSR status in NCM API",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("rejected", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{
						"ncm-ns.ncm-certificate": {
							href:    "https://ncm-server.local/requests/EufA12",
							checked: 1,
						},
					},
					mu: sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrCSRRejected,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Successfully sign certificate",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("accepted", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         nil,
			expectedCA:  []byte("-----BEGIN CERTIFICATE-----\nMn012Se...\n-----END CERTIFICATE-----\n"),
			expectedTLS: []byte("-----BEGIN CERTIFICATE-----\nL34FC3RT...\n-----END CERTIFICATE-----\n"),
		},
		{
			name: "Successfully sign certificate (after requeuing)",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientCSRStatus("accepted", nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{
						"ncm-ns.ncm-certificate": {
							href:    "https://ncm-server.local/requests/EufA12",
							checked: 1,
						},
					},
					mu: sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         nil,
			expectedCA:  []byte("-----BEGIN CERTIFICATE-----\nMn012Se...\n-----END CERTIFICATE-----\n"),
			expectedTLS: []byte("-----BEGIN CERTIFICATE-----\nL34FC3RT...\n-----END CERTIFICATE-----\n"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}

}

func TestRenew(t *testing.T) {
	type testCase struct {
		name        string
		cr          *cmapi.CertificateRequest
		p           *Provisioner
		err         error
		expectedCA  []byte
		expectedTLS []byte
	}

	run := func(t *testing.T, tc testCase) {
		ca, tls, _, err := tc.p.Renew(&cr, "cert-id")

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; want %s", tc.name, err.Error(), tc.err.Error())
		}

		if string(tc.expectedCA) != string(ca) {
			t.Errorf("%s failed; got %s; want %s", tc.name, string(ca), string(tc.expectedCA))
		}

		if string(tc.expectedTLS) != string(tls) {
			t.Errorf("%s failed; got %s; want %s", tc.name, string(tls), string(tc.expectedTLS))
		}
	}

	testCases := []testCase{
		{
			name: "Failed to get CAs",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, ErrFailedGetCAs),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrFailedGetCAs,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Failed to renew certificate",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientRenewCertificate(errors.New("cannot established connection"))),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         errors.New("failed to renew certificate"),
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "Successfully renew certificate",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientSendCSR(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil),
					unit.SetFakeClientRenewCertificate(nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         nil,
			expectedCA:  []byte("-----BEGIN CERTIFICATE-----\nMn012Se...\n-----END CERTIFICATE-----\n"),
			expectedTLS: []byte("-----BEGIN CERTIFICATE-----\nL34FC3RT...\n-----END CERTIFICATE-----\n"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}

}
