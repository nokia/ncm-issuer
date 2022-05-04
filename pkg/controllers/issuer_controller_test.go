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
	"testing"

	nokiaAPI "cm/api/v1"
)

const (
	ClusterIssuer = "ClusterIssuer"
	Issuer        = "Issuer"
)

type testCase struct {
	kind                         string
	name                         types.NamespacedName
	objects                      []client.Object
	expectedResult               ctrl.Result
	expectedError                error
	expectedReadyConditionStatus metav1.ConditionStatus
}

func TestIssuerReconcile(t *testing.T) {
	tests := map[string]testCase{
		"success": {
			name: types.NamespacedName{Namespace: "ncm-issuer", Name: "issuer1"},
			objects: []client.Object{
				&nokiaAPI.Issuer{
					TypeMeta: metav1.TypeMeta{
						Kind:       Issuer,
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ncm-issuer",
					}, Spec: nokiaAPI.IssuerSpec{
						NcmSERVER:            "127.0.0.1",
						CASNAME:              "CA1",
						CASHREF:              "kdhu84hrjl",
						LittleEndian:         true,
						ReenrollmentOnRenew:  true,
						UseProfileIDForRenew: true,
						NoRoot:               true,
						AuthSecretName:       "secretName1",
						ProfileId:            "100",
						TlsSecretName:        "secretName2",
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
				Kind:     Issuer,
				Scheme:   scheme,
				Clock:    clock.RealClock{},
				Recorder: record.NewFakeRecorder(10),
				Log:      testr.TestLogger{T: t}}

			ctx := context.TODO()
			result, err := issuerController.Reconcile(ctx, reconcile.Request{NamespacedName: testCase.name})
			assert.NoError(t, err)
			assert.Equal(t, ctrl.Result{}, result, "Unexpected result")
		})
	}
}
