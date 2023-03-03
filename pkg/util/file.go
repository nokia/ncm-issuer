package util

import (
	"fmt"
	"net/url"
	"os"

	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	"k8s.io/api/core/v1"
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

func GetSecretNamespace(issuer client.Object, req ctrl.Request) (string, error) {
	switch t := issuer.(type) {
	case *ncmv1.Issuer:
		return req.Namespace, nil
	case *ncmv1.ClusterIssuer:
		if t.Spec.AuthNamespace == "" {
			t.Spec.AuthNamespace = metav1.NamespaceDefault
		}
		return t.Spec.AuthNamespace, nil
	default:
		return "", fmt.Errorf("not an issuer type: %t", t)
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

// WritePEMToTempFile writes PEM to temporary file.
func WritePEMToTempFile(pem []byte) (string, error) {
	csrFile, err := os.CreateTemp("", "*.pem")
	if err != nil {
		return "", err
	}

	defer csrFile.Close()
	path := csrFile.Name()

	if _, err := csrFile.Write(pem); err != nil {
		return path, err
	}

	if err = csrFile.Sync(); err != nil {
		return path, err
	}

	return path, err
}

func GetPathFromCertHref(certHref string) (string, error) {
	parsedURL, err := url.Parse(certHref)
	if err != nil {
		return "", fmt.Errorf("cannot parsed given href: %s", certHref)
	}

	return parsedURL.Path, nil
}
