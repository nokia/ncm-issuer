package pkiutil

import (
	"fmt"
	cmv1 "github.com/nokia/ncm-issuer/api/v1"
	"k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetSpecAndStatus(issuer client.Object) (*cmv1.IssuerSpec, *cmv1.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *cmv1.Issuer:
		return &t.Spec, &t.Status, nil
	case *cmv1.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func GetSecretNamespace(issuer client.Object, req ctrl.Request) (string, error) {
	switch t := issuer.(type) {
	case *cmv1.Issuer:
		return req.Namespace, nil
	case *cmv1.ClusterIssuer:
		if t.Spec.AuthNamespace == "" {
			t.Spec.AuthNamespace = "default"
		}
		return t.Spec.AuthNamespace, nil
	default:
		return "", fmt.Errorf("not an issuer type: %t", t)
	}
}

func FindIfSecretExists(secretList v1.SecretList, secretName string) bool {
	for _, secret := range secretList.Items {
		if secret.Name == secretName {
			return true
		}
	}
	return false
}

func GetSecretObject(namespace string, name string, certID string) *v1.Secret {
	secret := v1.Secret{
		ObjectMeta: v12.ObjectMeta{
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

// MyCRDHasCondition will return true if the given MyCRD has a
// condition matching the provided MyCRDCondition.
// Only the Type and Status field will be used in the comparison, meaning that
// this function will return 'true' even if the Reason, Message and
// LastTransitionTime fields do not match.
func MyCRDHasCondition(status cmv1.IssuerStatus, c cmv1.IssuerCondition) bool {
	existingConditions := status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			return true
		}
	}
	return false
}
