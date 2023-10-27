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

package gen

import (
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

type FakeProvisioner struct {
	SignFn           func() ([]byte, []byte, string, error)
	RenewFn          func() ([]byte, []byte, string, error)
	PreventRenewalFn func() bool
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

func SetFakeProvisionerPreventRenewal(prevent bool) func(provisioner *FakeProvisioner) {
	return func(fp *FakeProvisioner) {
		fp.PreventRenewalFn = func() bool {
			return prevent
		}
	}
}

func (fp *FakeProvisioner) Sign(*cmapi.CertificateRequest) ([]byte, []byte, string, error) {
	return fp.SignFn()
}

func (fp *FakeProvisioner) Renew(*cmapi.CertificateRequest, string) ([]byte, []byte, string, error) {
	return fp.RenewFn()
}

func (fp *FakeProvisioner) PreventRenewal() bool {
	return fp.PreventRenewalFn()
}

func (fp *FakeProvisioner) Retire() {}
