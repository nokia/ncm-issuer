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
			name:        "cas-name-success",
			CAsHref:     "",
			CAsName:     "ncmCA2",
			CAsResponse: CAsResponse,
			isFindable:  true,
			expectedCA:  &crt2,
		},
		{
			name:        "cas-href-success",
			CAsHref:     "Mn012Se",
			CAsName:     "",
			CAsResponse: CAsResponse,
			isFindable:  true,
			expectedCA:  &crt1,
		},
		{
			name:        "cas-name-case-sensitive",
			CAsHref:     "",
			CAsName:     "NCMca2",
			CAsResponse: CAsResponse,
			isFindable:  false,
			expectedCA:  &ncmapi.CAResponse{},
		},
		{
			name:        "cas-href-case-sensitive",
			CAsHref:     "mN012sE",
			CAsName:     "",
			CAsResponse: CAsResponse,
			isFindable:  false,
			expectedCA:  &ncmapi.CAResponse{},
		},
		{
			name:        "found-ca-not-active",
			CAsHref:     "efG312Ed",
			CAsName:     "ncmCA3",
			CAsResponse: CAsResponse,
			isFindable:  false,
			expectedCA:  &ncmapi.CAResponse{},
		},
		{
			name:        "empty-cas-name-and-href",
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
			t.Fatalf("%s failed; got %s; want %s", tc.name, string(ca), string(tc.expectedCA))
		}

		if string(tc.expectedChain) != string(chain) {
			t.Fatalf("%s failed; got %s; want %s", tc.name, string(chain), string(tc.expectedChain))
		}
	}

	testCases := []testCase{
		{
			name: "get-chain-and-ca-success",
			fakeClient: unit.NewFakeClient(
				unit.SetFakeClientGetCA(nil),
				unit.SetFakeClientDownloadCertificate(nil),
				unit.SetFakeClientDownloadCertificateInPEM(nil)),
			err:           nil,
			expectedChain: []byte(""),
			expectedCA:    []byte("-----BEGIN CERTIFICATE-----\nMn012Se...\n-----END CERTIFICATE-----\n"),
		},
		{
			name: "cannot-download-certificate",
			fakeClient: unit.NewFakeClient(
				unit.SetFakeClientGetCA(nil),
				unit.SetFakeClientDownloadCertificate(errors.New("failed to download CA certificate")),
				unit.SetFakeClientDownloadCertificateInPEM(nil)),
			err:           errors.New("failed to download CA certificate"),
			expectedChain: []byte(""),
			expectedCA:    []byte(""),
		},
		{
			name: "cannot-download-certificate-in-pem",
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
			name:        "all-manipulation-data-set-to-false",
			config:      &cfg.NCMConfig{},
			expectedCA:  rootCA,
			expectedTLS: append(leafCert, append(signingCA, interCA...)...),
		},
		{
			name: "littleendian-set-to-true",
			config: &cfg.NCMConfig{
				LittleEndian: true,
			},
			expectedCA:  rootCA,
			expectedTLS: append(interCA, append(signingCA, leafCert...)...),
		},
		{
			name: "chaininsigner-set-to-true",
			config: &cfg.NCMConfig{
				ChainInSigner: true,
			},
			expectedCA:  append(signingCA, append(interCA, rootCA...)...),
			expectedTLS: append(leafCert, append(signingCA, interCA...)...),
		},
		{
			name: "littleendian-and-chaininsigner-set-to-true",
			config: &cfg.NCMConfig{
				LittleEndian:  true,
				ChainInSigner: true,
			},
			expectedCA:  append(rootCA, append(interCA, signingCA...)...),
			expectedTLS: append(interCA, append(signingCA, leafCert...)...),
		},
		{
			name: "onlyeecert-set-to-true",
			config: &cfg.NCMConfig{
				OnlyEECert: true,
			},
			expectedCA:  rootCA,
			expectedTLS: leafCert,
		},
		{
			name: "chaininsigner-and-onlyeecert-set-to-true",
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
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if string(tc.expectedCA) != string(ca) {
			t.Fatalf("%s failed; got %s; want %s", tc.name, string(ca), string(tc.expectedCA))
		}

		if string(tc.expectedTLS) != string(tls) {
			t.Fatalf("%s failed; got %s; want %s", tc.name, string(tls), string(tc.expectedTLS))
		}
	}

	cr.Annotations = map[string]string{
		cmapi.CertificateNameKey: "ncm-certificate",
	}

	testCases := []testCase{
		{
			name: "failed-get-cas",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "Mn012Se",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, ErrFailedGetCAs),
					unit.SetFakeClientGetCA(nil),
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
			name: "failed-find-ca",
			cr:   &cr,
			p: &Provisioner{
				NCMConfig: &cfg.NCMConfig{
					CAsHref: "eFgEf12",
				},
				NCMClient: unit.NewFakeClient(
					unit.SetFakeClientGetCAs(CAsResponse, nil),
					unit.SetFakeClientGetCA(nil),
					unit.SetFakeClientDownloadCertificate(nil),
					unit.SetFakeClientDownloadCertificateInPEM(nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         errors.New("has not been found"),
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "failed-send-csr",
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
					unit.SetFakeClientDownloadCertificateInPEM(nil)),
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
			name: "failed-check-csr-status",
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
			name: "csr-status-pending",
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
					unit.SetFakeClientCSRStatus(CSRStatusPending, nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrCSRNotAccepted,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "csr-status-rejected",
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
					unit.SetFakeClientCSRStatus(CSRStatusRejected, nil)),
				pendingCSRs: &PendingCSRsMap{
					pendingCSRs: map[string]*PendingCSR{},
					mu:          sync.RWMutex{},
				},
				log: &testr.TestLogger{T: t},
			},
			err:         ErrCSRRejected,
			expectedCA:  []byte(""),
			expectedTLS: []byte(""),
		},
		{
			name: "sign-success",
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
					unit.SetFakeClientCSRStatus(CSRStatusAccepted, nil)),
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
			name: "sign-success-after-requeuing",
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
					unit.SetFakeClientCSRStatus(CSRStatusAccepted, nil)),
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

func TestHandlingCSR(t *testing.T) {
	type testCase struct {
		name string
		cr   *cmapi.CertificateRequest
		p    *Provisioner
		err  error
	}

	run := func(t *testing.T, tc testCase) {
		_, _, _, err := tc.p.Sign(tc.cr)

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Fatalf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}
	}

	cr.Annotations = map[string]string{
		cmapi.CertificateNameKey: "ncm-certificate",
	}

	testCases := []testCase{
		{
			name: "csr-status-cannot-be-checked",
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
			err: errors.New("failed checking CSR status in NCM"),
		},
		{
			name: "csr-status-pending",
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
					unit.SetFakeClientCSRStatus(CSRStatusPending, nil)),
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
			err: ErrCSRNotAccepted,
		},
		{
			name: "csr-status-pending-but-exceeded-check-limit",
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
					unit.SetFakeClientCSRStatus(CSRStatusPending, nil)),
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
			err: ErrCSRCheckLimitExceeded,
		},
		{
			name: "csr-status-postponed",
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
					unit.SetFakeClientCSRStatus(CSRStatusPostponed, nil)),
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
			err: ErrCSRRejected,
		},
		{
			name: "csr-status-approved",
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
					unit.SetFakeClientCSRStatus(CSRStatusApproved, nil)),
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
			err: ErrCSRNotAccepted,
		},
		{
			name: "csr-status-rejected",
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
					unit.SetFakeClientCSRStatus(CSRStatusRejected, nil)),
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
			err: ErrCSRRejected,
		},
		{
			name: "csr-status-unexpected",
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
					unit.SetFakeClientCSRStatus("unexpected", errors.New("unexpected"))),
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
			err: errors.New("unexpected"),
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
			t.Fatalf("%s failed; got %s; want %s", tc.name, string(ca), string(tc.expectedCA))
		}

		if string(tc.expectedTLS) != string(tls) {
			t.Fatalf("%s failed; got %s; want %s", tc.name, string(tls), string(tc.expectedTLS))
		}
	}

	testCases := []testCase{
		{
			name: "failed-get-cas",
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
			name: "failed-renew-certificate",
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
			name: "renew-success",
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
