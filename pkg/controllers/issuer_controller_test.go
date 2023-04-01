package controllers

import (
	"context"
	"errors"
	"github.com/go-logr/logr/testr"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	"github.com/nokia/ncm-issuer/pkg/provisioner"
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
)

const (
	Issuer        = "Issuer"
	ClusterIssuer = "ClusterIssuer"
	Unrecognised  = "Unrecognised"
)

func TestIssuerReconcile(t *testing.T) {
	type testCase struct {
		name           string
		kind           string
		namespacedName types.NamespacedName
		objects        []client.Object
		err            error
		expectedResult ctrl.Result
		expectedStatus *ncmv1.IssuerStatus
	}

	scheme := runtime.NewScheme()
	require.NoError(t, ncmv1.AddToScheme(scheme))
	require.NoError(t, v1.AddToScheme(scheme))

	clk := clock.RealClock{}
	now := metav1.NewTime(clk.Now().Truncate(time.Second))

	run := func(t *testing.T, tc testCase) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(tc.objects...).
			Build()

		p := provisioner.NewProvisionersMap()
		controller := &IssuerReconciler{
			Client:       fakeClient,
			Kind:         tc.kind,
			Scheme:       scheme,
			Clock:        clk,
			Recorder:     record.NewFakeRecorder(10),
			Provisioners: p,
			Log:          testr.New(t),
		}

		_, err := controller.Reconcile(context.TODO(), reconcile.Request{NamespacedName: tc.namespacedName})

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if tc.expectedStatus != nil && len(tc.expectedStatus.Conditions) != 0 {
			issuer, _ := controller.newIssuer()
			if err := fakeClient.Get(context.TODO(), tc.namespacedName, issuer); err != nil {
				t.Errorf("%s failed; expected to retrieve issuer err: %s", tc.name, err.Error())
			}
			_, issuerStatus, _ := GetSpecAndStatus(issuer)

			if diff := cmp.Diff(tc.expectedStatus, issuerStatus); diff != "" {
				t.Errorf("%s failed; returned and expected issuer status is not the same (-want +got)\n%s", tc.name, diff)
			}

			if tc.err == nil {
				if _, ok := controller.Provisioners.Get(tc.namespacedName); !ok {
					t.Fatalf("%s failed; expected to find ready to use ncm provisioner", tc.name)
				}
			}
		}
	}

	testCases := []testCase{
		{
			name:           "issuer-kind-unrecognised",
			kind:           Unrecognised,
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
		},
		{
			name:           "issuer-not-found",
			kind:           Issuer,
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
		},
		{
			name:           "issuer-auth-secret-not-found",
			kind:           Issuer,
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						AuthNamespace:  "ncm-ns",
						AuthSecretName: "ncm-auth-secret",
					},
				},
			},
			err: errors.New("secrets \"ncm-auth-secret\" not found"),
			expectedStatus: &ncmv1.IssuerStatus{
				Conditions: []ncmv1.IssuerCondition{
					{
						Type:               ncmv1.IssuerConditionReady,
						Status:             ncmv1.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "NotFound",
						Message:            "Failed to retrieve auth secret err: secrets \"ncm-auth-secret\" not found",
					},
				},
			},
		},
		{
			name:           "issuer-auth-data-not-useful",
			kind:           Issuer,
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						NCMServer:      "https://ncm-server.local",
						AuthNamespace:  "ncm-ns",
						AuthSecretName: "ncm-auth-secret",
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-auth-secret",
					},
					Data: map[string][]byte{},
				},
			},
			err: errors.New("incorrect authentication data: missing username or usrpassword"),
			expectedStatus: &ncmv1.IssuerStatus{
				Conditions: []ncmv1.IssuerCondition{
					{
						Type:               ncmv1.IssuerConditionReady,
						Status:             ncmv1.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Error",
						Message:            "Failed to validate config provided in spec: incorrect authentication data: missing username or usrpassword",
					},
				},
			},
		},
		{
			name:           "issuer-tls-secret-not-found",
			kind:           Issuer,
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						AuthNamespace:  "ncm-ns",
						AuthSecretName: "ncm-auth-secret",
						TLSSecretName:  "ncm-tls-secret",
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-auth-secret",
					},
					Data: map[string][]byte{},
				},
			},
			err: errors.New("secrets \"ncm-tls-secret\" not found"),
			expectedStatus: &ncmv1.IssuerStatus{
				Conditions: []ncmv1.IssuerCondition{
					{
						Type:               ncmv1.IssuerConditionReady,
						Status:             ncmv1.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "NotFound",
						Message:            "Failed to retrieve auth secret err: secrets \"ncm-tls-secret\" not found",
					},
				},
			},
		},
		{
			name:           "issuer-tls-data-not-useful",
			kind:           Issuer,
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						NCMServer:      "https://ncm-server.local",
						CAsName:        "ncmCA",
						AuthNamespace:  "ncm-ns",
						AuthSecretName: "ncm-auth-secret",
						TLSSecretName:  "ncm-tls-secret",
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-auth-secret",
					},
					Data: map[string][]byte{
						"username":    []byte("ncm-user"),
						"usrPassword": []byte("ncm-user-password"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-tls-secret",
					},
					Data: map[string][]byte{},
				},
			},
			err: errors.New("incorrect TLS data: missing cacert, key or cert in TLS secret"),
			expectedStatus: &ncmv1.IssuerStatus{
				Conditions: []ncmv1.IssuerCondition{
					{
						Type:               ncmv1.IssuerConditionReady,
						Status:             ncmv1.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Error",
						Message:            "Failed to validate config provided in spec: incorrect TLS data: missing cacert, key or cert in TLS secret",
					},
				},
			},
		},
		{
			name:           "issuer-cannot-create-new-provisioner",
			kind:           Issuer,
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						NCMServer:      "https://ncm-server.local:-8081",
						CAsName:        "ncmCA",
						AuthNamespace:  "ncm-ns",
						AuthSecretName: "ncm-auth-secret",
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-auth-secret",
					},
					Data: map[string][]byte{
						"username":    []byte("ncm-user"),
						"usrPassword": []byte("ncm-user-password"),
					},
				},
			},
			err: errors.New("NCM API Client Error reason: cannot create new API client, err: parse \"https://ncm-server.local:-8081\""),
			expectedStatus: &ncmv1.IssuerStatus{
				Conditions: []ncmv1.IssuerCondition{
					{
						Type:               ncmv1.IssuerConditionReady,
						Status:             ncmv1.ConditionFalse,
						LastTransitionTime: &now,
						Reason:             "Error",
						Message:            "Failed to create new provisioner err: NCM API Client Error reason: cannot create new API client, err: parse \"https://ncm-server.local:-8081\": invalid port \":-8081\" after host",
					},
				},
			},
		},
		{
			name:           "issuer-success",
			kind:           Issuer,
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						NCMServer:      "https://ncm-server.local:8081",
						CAsName:        "ncmCA",
						AuthNamespace:  "ncm-ns",
						AuthSecretName: "ncm-auth-secret",
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-auth-secret",
					},
					Data: map[string][]byte{
						"username":    []byte("ncm-user"),
						"usrPassword": []byte("ncm-user-password"),
					},
				},
			},
			expectedStatus: &ncmv1.IssuerStatus{
				Conditions: []ncmv1.IssuerCondition{
					{
						Type:               ncmv1.IssuerConditionReady,
						Status:             ncmv1.ConditionTrue,
						LastTransitionTime: &now,
						Reason:             "Verified",
						Message:            "Signing CA verified and ready to sign certificates",
					},
				},
			},
		},
		{
			name:           "cluster-issuer-success",
			kind:           ClusterIssuer,
			namespacedName: types.NamespacedName{Namespace: v1.NamespaceDefault, Name: "ncm-cluster-issuer"},
			objects: []client.Object{
				&ncmv1.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: v1.NamespaceDefault,
						Name:      "ncm-cluster-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						NCMServer:      "https://ncm-server.local:8081",
						CAsName:        "ncmCA",
						AuthNamespace:  v1.NamespaceDefault,
						AuthSecretName: "ncm-auth-secret",
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: v1.NamespaceDefault,
						Name:      "ncm-auth-secret",
					},
					Data: map[string][]byte{
						"username":    []byte("ncm-user"),
						"usrPassword": []byte("ncm-user-password"),
					},
				},
			},
			expectedStatus: &ncmv1.IssuerStatus{
				Conditions: []ncmv1.IssuerCondition{
					{
						Type:               ncmv1.IssuerConditionReady,
						Status:             ncmv1.ConditionTrue,
						LastTransitionTime: &now,
						Reason:             "Verified",
						Message:            "Signing CA verified and ready to sign certificates",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}
