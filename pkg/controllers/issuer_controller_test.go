package controllers

import (
	"context"
	testr "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"strings"
	"testing"

	nokiaAPI "github.com/nokia/ncm-issuer/api/v1"
)

const (
	ClusterIssuer = "ClusterIssuer"
	Issuer        = "Issuer"
)

func TestIssuerReconcile(t *testing.T) {

	type testCase struct {
		kind             string
		name             types.NamespacedName
		objects          []client.Object
		expectedResult   ctrl.Result
		expectedErrorMsg string
	}

	tests := map[string]testCase{
		"successIssuer": {
			name: types.NamespacedName{Namespace: "ncm-issuer", Name: "issuer"},
			kind: Issuer,
			objects: []client.Object{
				&nokiaAPI.Issuer{
					TypeMeta: metav1.TypeMeta{
						Kind:       Issuer,
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer",
						Namespace: "ncm-issuer",
					}, Spec: nokiaAPI.IssuerSpec{
						NCMServer:            "127.0.0.1",
						NCMServer2:           "",
						CAsName:              "CA1",
						CAsHREF:              "kdhu84hrjl",
						LittleEndian:         true,
						ReenrollmentOnRenew:  true,
						UseProfileIDForRenew: true,
						NoRoot:               true,
						AuthSecretName:       "secretName1",
						ProfileId:            "100",
						TLSSecretName:        "secretName2",
					},
					Status: nokiaAPI.IssuerStatus{Conditions: []nokiaAPI.IssuerCondition{
						{Type: "",
							Status:             "",
							LastTransitionTime: nil,
						},
					}},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secretName1",
						Namespace: "ncm-issuer",
					},
					Data: map[string][]byte{
						"username":    []byte("green_user"),
						"usrPassword": []byte("green_password"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secretName2",
						Namespace: "ncm-issuer",
					},
					Data: map[string][]byte{
						"key":    []byte("randomkeyhere"),
						"cert":   []byte("certpemhere"),
						"cacert": []byte("cacertpemhere"),
					},
				},
			},
			expectedErrorMsg: "",
			expectedResult:   ctrl.Result{},
		},
		"successClusterIssuer": {
			name: types.NamespacedName{Namespace: "ncm-issuer", Name: "clsissuer"},
			kind: ClusterIssuer,
			objects: []client.Object{
				&nokiaAPI.ClusterIssuer{
					TypeMeta: metav1.TypeMeta{
						Kind:       ClusterIssuer,
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "clsissuer",
						Namespace: "ncm-issuer",
					}, Spec: nokiaAPI.IssuerSpec{
						NCMServer:            "127.0.0.1",
						NCMServer2:           "",
						CAsName:              "CA1",
						CAsHREF:              "kdhu84hrjl",
						LittleEndian:         true,
						ReenrollmentOnRenew:  true,
						UseProfileIDForRenew: true,
						NoRoot:               true,
						AuthSecretName:       "secretName1",
						ProfileId:            "100",
						TLSSecretName:        "secretName2",
						AuthNamespace:        "namespaceAuth",
					},
					Status: nokiaAPI.IssuerStatus{Conditions: []nokiaAPI.IssuerCondition{
						{Type: "",
							Status:             "",
							LastTransitionTime: nil,
						},
					}},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secretName1",
						Namespace: "namespaceAuth",
					},
					Data: map[string][]byte{
						"username":    []byte("green_user"),
						"usrPassword": []byte("green_password"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secretName2",
						Namespace: "namespaceAuth",
					},
					Data: map[string][]byte{
						"key":    []byte("randomkeyhere"),
						"cert":   []byte("certpemhere"),
						"cacert": []byte("cacertpemhere"),
					},
				},
			},
			expectedErrorMsg: "",
			expectedResult:   ctrl.Result{},
		},
		"missingServerIssuer": {
			name: types.NamespacedName{Namespace: "ncm-issuer", Name: "issuer"},
			kind: Issuer,
			objects: []client.Object{
				&nokiaAPI.Issuer{
					TypeMeta: metav1.TypeMeta{
						Kind:       Issuer,
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer",
						Namespace: "ncm-issuer",
					}, Spec: nokiaAPI.IssuerSpec{
						NCMServer:            "",
						NCMServer2:           "",
						CAsName:              "CA1",
						CAsHREF:              "kdhu84hrjl",
						LittleEndian:         true,
						ReenrollmentOnRenew:  true,
						UseProfileIDForRenew: true,
						NoRoot:               true,
						AuthSecretName:       "secretName1",
						ProfileId:            "100",
						TLSSecretName:        "secretName2",
					},
					Status: nokiaAPI.IssuerStatus{Conditions: []nokiaAPI.IssuerCondition{
						{Type: "",
							Status:             "",
							LastTransitionTime: nil,
						},
					}},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secretName1",
						Namespace: "namespaceAuth",
					},
					Data: map[string][]byte{
						"username":    []byte("green_user"),
						"usrPassword": []byte("green_password"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secretName2",
						Namespace: "namespaceAuth",
					},
					Data: map[string][]byte{
						"key":    []byte("randomkeyhere"),
						"cert":   []byte("certpemhere"),
						"cacert": []byte("cacertpemhere"),
					},
				},
			},
			expectedErrorMsg: "incorrect setting",
			expectedResult:   ctrl.Result{},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, nokiaAPI.AddToScheme(scheme))
	require.NoError(t, v1.AddToScheme(scheme))

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(testCase.objects...).Build()
			issuerController := &IssuerReconciler{
				Client:   fakeClient,
				Kind:     testCase.kind,
				Scheme:   scheme,
				Clock:    clock.RealClock{},
				Recorder: record.NewFakeRecorder(10),
				Log:      testr.TestLogger{T: t}}

			ctx := context.TODO()
			result, err := issuerController.Reconcile(ctx, reconcile.Request{NamespacedName: testCase.name})
			if testCase.expectedErrorMsg != "" {
				if !ErrorContains(err, testCase.expectedErrorMsg) {
					t.Errorf("Unexpected error: %v", err)
				}
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedResult, result, "Unexpected result")
		})
	}
}

func ErrorContains(resultErr error, wantedErrMsg string) bool {
	if resultErr == nil {
		return wantedErrMsg == ""
	}
	if wantedErrMsg == "" {
		return false
	}
	return strings.Contains(resultErr.Error(), wantedErrMsg)
}
