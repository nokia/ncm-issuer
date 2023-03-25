package provisioner

import (
	"errors"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/nokia/ncm-issuer/pkg/cfg"
	"github.com/nokia/ncm-issuer/pkg/ncmapi"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// SingleCSRCheckLimit defines limit for checking single CSR status returned by NCM.
	// In case of need for manual approval ncm-issuer gives operator around 24h (1440m) to
	// accept CSR manually in NCM before rejecting that request.
	SingleCSRCheckLimit = 1440

	CSRStatusAccepted  = "accepted"
	CSRStatusApproved  = "approved"
	CSRStatusPending   = "pending"
	CSRStatusPostponed = "postponed"
	CSRStatusRejected  = "rejected"
)

var (
	ErrFailedGetCAs          = errors.New("failed to get CAs")
	ErrCSRNotAccepted        = errors.New("CSR has not been accepted yet")
	ErrCSRRejected           = errors.New("CSR has been rejected")
	ErrCSRCheckLimitExceeded = errors.New("CSR has not been accepted for too long")
)

// ProvisionersMap stores prepared (NCM API Client is configured) and ready to
// use provisioner.
type ProvisionersMap struct {
	Provisioners map[types.NamespacedName]ExternalProvisioner
	mu           sync.RWMutex
}

func NewProvisionersMap() *ProvisionersMap {
	return &ProvisionersMap{
		Provisioners: map[types.NamespacedName]ExternalProvisioner{},
		mu:           sync.RWMutex{},
	}
}

func (pm *ProvisionersMap) Get(NamespacedName types.NamespacedName) (ExternalProvisioner, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	p, ok := pm.Provisioners[NamespacedName]
	return p, ok
}

func (pm *ProvisionersMap) AddOrReplace(NamespacedName types.NamespacedName, provisioner ExternalProvisioner) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, ok := pm.Provisioners[NamespacedName]; !ok {
		pm.Provisioners[NamespacedName] = provisioner
	} else {
		// The existing provisioner has been found, but IssuerReconcile
		// was triggered again, which may involve a change in configuration.
		delete(pm.Provisioners, NamespacedName)
		pm.Provisioners[NamespacedName] = provisioner
	}
}

// Provisioner allows Sign or Renew certificate using NCMClient.
type Provisioner struct {
	NCMConfig   *cfg.NCMConfig
	NCMClient   ncmapi.ExternalClient
	pendingCSRs *PendingCSRsMap
	log         logr.Logger
}

func NewProvisioner(NCMCfg *cfg.NCMConfig, log logr.Logger) (*Provisioner, error) {
	c, err := ncmapi.NewClient(NCMCfg, log)
	if err != nil {
		return nil, err
	}

	p := &Provisioner{
		NCMConfig: NCMCfg,
		NCMClient: c,
		pendingCSRs: &PendingCSRsMap{
			pendingCSRs: map[string]*PendingCSR{},
			mu:          sync.RWMutex{},
		},
		log: log,
	}

	return p, nil
}

// Sign uses NCMClient to communicate with NCM API to sign CertificateRequest.
// NCM policy defines few statuses for CSR, which must be correctly handled
// by ncm-issuer. Thus, CSR status in NCM is checked every time to deduce current
// state - Provisioner stores in pendingCSRs href to pending CSR if request has not been
// accepted during first CertificateRequest.
func (p *Provisioner) Sign(cr *cmapi.CertificateRequest) ([]byte, []byte, string, error) {
	casResponse, err := p.NCMClient.GetCAs()
	if err != nil {
		return nil, nil, "", ErrFailedGetCAs
	}

	signingCA, found := findCA(casResponse, p.NCMConfig.CAsHref, p.NCMConfig.CAsName)
	if !found {
		return nil, nil, "", fmt.Errorf("CA certificate with the given HREF or NAME has not been found")
	}

	certChain, wantedCA, err := p.getChainAndWantedCA(signingCA)
	if err != nil {
		return nil, nil, "", err
	}

	if has := p.pendingCSRs.Has(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey]); has {
		pendingCSR := p.pendingCSRs.Get(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey])
		csrStatusResp, err := p.NCMClient.CheckCSRStatus(pendingCSR.href)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed checking CSR status in NCM, its href: %s, err: %v", pendingCSR.href, err)
		}

		switch status := csrStatusResp.Status; status {
		case CSRStatusAccepted:
			leafCertURLPath, _ := ncmapi.GetPathFromCertHref(csrStatusResp.Certificate)
			leafCertInPEM, _ := p.NCMClient.DownloadCertificateInPEM(leafCertURLPath)
			if err != nil {
				return nil, nil, "", fmt.Errorf("failed to download end-entity certificate in PEM, its href: %s, err: %v", csrStatusResp.Certificate, err)
			}

			p.pendingCSRs.Delete(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey])
			ca, tls := p.prepareCAAndTLS(wantedCA, leafCertInPEM, certChain)
			return ca, tls, csrStatusResp.Certificate, nil
		case CSRStatusApproved:
			// CSRStatusApproved means that CSR has been approved (by operator) but NCM
			// has yet to Sign generated certificate - this means that in the near future
			// the status of CSR will be CSRStatusAccepted, and we will be able to
			// download that certificate by using NCMClient. Thus, we need to
			// return ErrCSRNotAccepted to requeue CertificateRequest and reset
			// "checked" value in PendingCSR to avoid exceeding SingleCSRCheckLimit.

			p.pendingCSRs.ResetCheckCounter(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey])
			return nil, nil, "", ErrCSRNotAccepted
		case CSRStatusPending:
			if pendingCSR.checked <= SingleCSRCheckLimit {
				p.pendingCSRs.Increment(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey])
				return nil, nil, "", ErrCSRNotAccepted
			}
			// If the status of CSR for a long period of time was CSRStatusPending
			// ncm-issuer will reject PendingCSR returning ErrCSRCheckLimitExceeded
			// to avoid redundant requeuing CertificateRequest - further actions
			// should be taken by operator (certificate re-enrollment in k8s cluster).

			p.pendingCSRs.Delete(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey])
			return nil, nil, "", ErrCSRCheckLimitExceeded
		case CSRStatusPostponed:
			// CSRStatusPostponed means that the previous status of CSR was CSRStatusPending.
			// CSR in NCM still can be manipulated, but ncm-issuer is rejecting PendingCSR - further
			// actions should be taken by operator (certificate re-enrollment in k8s cluster).

			p.pendingCSRs.Delete(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey])
			return nil, nil, "", ErrCSRRejected
		case CSRStatusRejected:
			p.pendingCSRs.Delete(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey])
			return nil, nil, "", ErrCSRRejected
		default:
			return nil, nil, "", fmt.Errorf("got unexpected status: %s", status)
		}
	}

	csrResp, err := p.NCMClient.SendCSR(cr.Spec.Request, signingCA, p.NCMConfig.ProfileID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to send CSR, err: %v", err)
	}

	requestedCertURLPath, _ := ncmapi.GetPathFromCertHref(csrResp.Href)
	csrStatusResp, err := p.NCMClient.CheckCSRStatus(requestedCertURLPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed checking CSR status in NCM, its href: %s, err: %v", csrResp.Href, err)
	}

	if status := csrStatusResp.Status; status == CSRStatusRejected {
		return nil, nil, "", ErrCSRRejected
	} else if status != CSRStatusAccepted {
		p.pendingCSRs.Add(cr.Namespace, cr.Annotations[cmapi.CertificateNameKey], csrResp.Href)
		return nil, nil, "", ErrCSRNotAccepted
	}

	leafCertURLPath, _ := ncmapi.GetPathFromCertHref(csrStatusResp.Certificate)
	leafCertInPEM, _ := p.NCMClient.DownloadCertificateInPEM(leafCertURLPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to download end-entity certificate in PEM, its href: %s, err: %v", csrStatusResp.Certificate, err)
	}

	ca, tls := p.prepareCAAndTLS(wantedCA, leafCertInPEM, certChain)
	return ca, tls, csrStatusResp.Certificate, nil
}

// Renew uses NCMClient to communicate with NCM API to renew existing
// certificate.
func (p *Provisioner) Renew(cr *cmapi.CertificateRequest, certID string) ([]byte, []byte, string, error) {
	casResponse, err := p.NCMClient.GetCAs()
	if err != nil {
		return nil, nil, "", ErrFailedGetCAs
	}

	singingCA, found := findCA(casResponse, p.NCMConfig.CAsHref, p.NCMConfig.CAsName)
	if !found {
		return nil, nil, "", fmt.Errorf("CA certificate with the given HREF or NAME has not been found")
	}

	certChain, wantedCA, err := p.getChainAndWantedCA(singingCA)
	if err != nil {
		return nil, nil, "", err
	}

	certURLPath, _ := ncmapi.GetPathFromCertHref(certID)
	renewCertResp, err := p.NCMClient.RenewCertificate(certURLPath, cr.Spec.Duration, p.NCMConfig.ProfileID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to renew certificate, its href: %s, err: %v", certID, err)
	}

	renewedCertURLPath, _ := ncmapi.GetPathFromCertHref(renewCertResp.Certificate)
	leafCertInPEM, err := p.NCMClient.DownloadCertificateInPEM(renewedCertURLPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to download renewed certificate in PEM, its href: %s, err: %v", renewCertResp.Certificate, err)
	}

	ca, tls := p.prepareCAAndTLS(wantedCA, leafCertInPEM, certChain)
	return ca, tls, renewCertResp.Certificate, nil
}

// getChainAndWantedCA gets PEM chain and CA certificate using NCMClient, those
// values are needed for both Sign and Renew operations. The order of bytes
// in PEM chain is defined by NCMConfig which also defines which CA certificate
// should be taken into consideration when selecting proper ca.crt
// (given CA certificate in NCMConfig or root CA certificate).
func (p *Provisioner) getChainAndWantedCA(signingCA *ncmapi.CAResponse) ([]byte, []byte, error) {
	var certChain []byte
	lastCheckedCA := signingCA

	for {
		p.log.Info("Last checked CA certificate in chain", "href", lastCheckedCA.Href)

		lastCheckedCAURLPath, _ := ncmapi.GetPathFromCertHref(lastCheckedCA.Certificates["active"])
		currentCACert, err := p.NCMClient.DownloadCertificate(lastCheckedCAURLPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to download CA certificate, its href: %s, err: %v", lastCheckedCA.Certificates["active"], err)
		}

		if isRootCA(lastCheckedCA, currentCACert) {
			break
		}

		currentCACertInPEM, err := p.NCMClient.DownloadCertificateInPEM(lastCheckedCAURLPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to download CA certificate in PEM, its href: %s, err: %v", lastCheckedCA.Certificates["active"], err)
		}
		certChain = addCertToChain(currentCACertInPEM, certChain, p.NCMConfig.LittleEndian)

		lastCheckedCAURLPath, _ = ncmapi.GetPathFromCertHref(currentCACert.IssuerCA)
		lastCheckedCA, err = p.NCMClient.GetCA(lastCheckedCAURLPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get CA certificate, its href: %s, err: %v", currentCACert.IssuerCA, err)
		}
	}

	wantedCA := p.getWantedCA(signingCA, lastCheckedCA)
	p.log.Info("Signing CA certificate was found and selected according to configuration", "isRootCA", !p.NCMConfig.NoRoot || p.NCMConfig.ChainInSigner, "Name", wantedCA.Name)
	wantedCAURLPath, _ := ncmapi.GetPathFromCertHref(wantedCA.Certificates["active"])
	wantedCAInPEM, err := p.NCMClient.DownloadCertificateInPEM(wantedCAURLPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download signing (root) CA in PEM, its href: %s, err: %v", wantedCA.Certificates["active"], err)
	}

	return certChain, wantedCAInPEM, nil
}

func (p *Provisioner) getWantedCA(signingCA, rootCA *ncmapi.CAResponse) *ncmapi.CAResponse {
	if p.NCMConfig.NoRoot && !p.NCMConfig.ChainInSigner {
		return signingCA
	}
	return rootCA
}

// prepareCAAndTLS prepares values needed for certificate (ca.crt and tls.crt)
// according to NCMConfig.
func (p *Provisioner) prepareCAAndTLS(wantedCA, leafCert, certChain []byte) ([]byte, []byte) {
	var ca, tls []byte
	if p.NCMConfig.ChainInSigner {
		var certChainWithRoot []byte
		certChainWithRoot = append(certChainWithRoot, certChain...)
		certChainWithRoot = addCertToChain(wantedCA, certChainWithRoot, p.NCMConfig.LittleEndian)
		ca = certChainWithRoot
	} else {
		ca = wantedCA
	}

	if !p.NCMConfig.OnlyEECert {
		certChain = addLeafCertToChain(leafCert, certChain, p.NCMConfig.LittleEndian)
		tls = certChain
	} else {
		tls = leafCert
	}

	return ca, tls
}
