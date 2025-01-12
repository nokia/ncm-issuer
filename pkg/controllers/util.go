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

package controllers

import (
	"fmt"
	"strings"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	ncmutil "github.com/nokia/ncm-issuer/pkg/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetSpecAndStatus(issuer client.Object) (*ncmv1.IssuerSpec, *ncmv1.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *ncmv1.Issuer:
		return &t.Spec, &t.Status, nil
	case *ncmv1.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func GetSecretNamespace(issuer client.Object, req ctrl.Request) string {
	switch t := issuer.(type) {
	case *ncmv1.Issuer:
		return req.Namespace
	case *ncmv1.ClusterIssuer:
		if t.Spec.AuthNamespace == "" {
			t.Spec.AuthNamespace = metav1.NamespaceDefault
		}
		return t.Spec.AuthNamespace
	default:
		return ""
	}
}

// IssuerHasCondition will return true if the given issuer has a
// condition matching the provided IssuerCondition.
// Only the Type and Status field will be used in the comparison, meaning that
// this function will return 'true' even if the Reason, Message and
// LastTransitionTime fields do not match.
func IssuerHasCondition(status ncmv1.IssuerStatus, c ncmv1.IssuerCondition) bool {
	existingConditions := status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			return true
		}
	}
	return false
}

// IssuerHasCondition will return true if the given issuer has a
// condition matching the provided IssuerCondition.
// The Status, Reason and Message will be used for comparison.
func IssuerHasConditionAndReasonAndMessage(status ncmv1.IssuerStatus, c ncmv1.IssuerCondition) bool {
	existingConditions := status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status && c.Reason == cond.Reason && c.Message == cond.Message {
			return true
		}
	}
	return false
}

func GetCertIDSecret(namespace string, name string, certID string) *v1.Secret {
	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		StringData: map[string]string{
			"cert-id": certID,
		},
		Type: v1.SecretTypeOpaque,
	}
	return &secret
}

func validateCertificateRequest(cr *cmapi.CertificateRequest) error {
	if len(cr.Spec.Request) == 0 {
		return fmt.Errorf("certificate request is empty")
	}

	csr, err := ncmutil.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return fmt.Errorf("failed to decode CSR for validation: %w", err)
	}

	if len(csr.Subject.CommonName) == 0 && len(csr.IPAddresses) == 0 && len(csr.DNSNames) == 0 && len(csr.EmailAddresses) == 0 {
		return fmt.Errorf("at least one of field should be included in certificate spec: commonName, ipAddresses, dnsNames or emailAddresses")
	}

	return nil
}

func errorContains(err error, str string) bool {
	return strings.Contains(err.Error(), str)
}
