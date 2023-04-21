package gen

import (
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

type FakeProvisioner struct {
	SignFn  func() ([]byte, []byte, string, error)
	RenewFn func() ([]byte, []byte, string, error)
}

func NewFakeProvisioner(mods ...func(fakeProvisioner *FakeProvisioner)) *FakeProvisioner {
	fp := &FakeProvisioner{}
	for _, mod := range mods {
		mod(fp)
	}
	return fp
}

func SetFakeProvisionerSign(ca, tls []byte, certID string) func(*FakeProvisioner) {
	return func(fp *FakeProvisioner) {
		fp.SignFn = func() ([]byte, []byte, string, error) {
			return ca, tls, certID, nil
		}
	}
}

func SetFakeProvisionerSignError(err error) func(*FakeProvisioner) {
	return func(fp *FakeProvisioner) {
		fp.SignFn = func() ([]byte, []byte, string, error) {
			return nil, nil, "", err
		}
	}
}

func SetFakeProvisionerRenew(ca, tls []byte, certID string) func(*FakeProvisioner) {
	return func(fp *FakeProvisioner) {
		fp.RenewFn = func() ([]byte, []byte, string, error) {
			return ca, tls, certID, nil
		}
	}
}

func SetFakeProvisionerRenewError(err error) func(*FakeProvisioner) {
	return func(fp *FakeProvisioner) {
		fp.RenewFn = func() ([]byte, []byte, string, error) {
			return nil, nil, "", err
		}
	}
}

func (fp *FakeProvisioner) Sign(*cmapi.CertificateRequest) ([]byte, []byte, string, error) {
	return fp.SignFn()
}

func (fp *FakeProvisioner) Renew(*cmapi.CertificateRequest, string) ([]byte, []byte, string, error) {
	return fp.RenewFn()
}

func (fp *FakeProvisioner) Retire() {}
