package controllers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/google/go-cmp/cmp"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	"github.com/nokia/ncm-issuer/pkg/provisioner"
	"github.com/nokia/ncm-issuer/test/unit/gen"
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

var (
	errAPINotReachable = errors.New("not reachable NCM API")
)

func TestCertificateRequestReconcile(t *testing.T) {
	type testCase struct {
		name                    string
		namespacedName          types.NamespacedName
		issuerName              types.NamespacedName
		provisioner             *gen.FakeProvisioner
		objects                 []client.Object
		err                     error
		expectedResult          ctrl.Result
		expectedConditionStatus cmmeta.ConditionStatus
		expectedConditionReason string
	}

	scheme := runtime.NewScheme()
	require.NoError(t, ncmv1.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, v1.AddToScheme(scheme))

	clk := clock.RealClock{}

	injectProvisioner := func(name types.NamespacedName, p *gen.FakeProvisioner) *provisioner.ProvisionersMap {
		pm := provisioner.NewProvisionersMap()
		pm.AddOrReplace(name, p)
		return pm
	}

	generateCSR := func() []byte {
		keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

		subj := pkix.Name{
			CommonName:   "ncm-cert.local",
			Country:      []string{"PL"},
			Organization: []string{"Nokia"},
		}

		template := &x509.CertificateRequest{
			Subject:            subj,
			SignatureAlgorithm: x509.SHA256WithRSA,
		}
		csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, template, keyBytes)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	}

	run := func(t *testing.T, tc testCase) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(tc.objects...).
			Build()

		controller := &CertificateRequestReconciler{
			Client:       fakeClient,
			Scheme:       scheme,
			Clock:        clk,
			Recorder:     record.NewFakeRecorder(10),
			Provisioners: injectProvisioner(tc.issuerName, tc.provisioner),
			Log:          testr.New(t),
		}

		result, err := controller.Reconcile(context.TODO(), reconcile.Request{NamespacedName: tc.namespacedName})

		if tc.err != nil && err != nil && !strings.Contains(err.Error(), tc.err.Error()) {
			t.Errorf("%s failed; expected error containing %s; got %s", tc.name, tc.err.Error(), err.Error())
		}

		if diff := cmp.Diff(tc.expectedResult, result); diff != "" {
			t.Errorf("%s failed; returned and expected result is not the same (-want +got)\n%s", tc.name, diff)
		}

		cr := &cmapi.CertificateRequest{}
		err = fakeClient.Get(context.TODO(), tc.namespacedName, cr)
		require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
		if err == nil {
			condition := apiutil.GetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady)
			if tc.expectedConditionStatus != "" && condition != nil && tc.expectedConditionStatus != condition.Status {
				t.Errorf("%s failed; returned and expected cr status is not the same; want %s; got %s", tc.name, tc.expectedConditionStatus, condition.Status)
			}

			if tc.expectedConditionReason != "" && condition != nil && tc.expectedConditionReason != condition.Reason {
				t.Errorf("%s failed; returned and expected cr reason is not the same; want %s; got %s", tc.name, tc.expectedConditionReason, condition.Reason)
			}
		}
	}

	testCases := []testCase{
		{
			name:           "certificate-request-not-found",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
		},
		{
			name:           "issuer-ref-foreign-group",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Group: "foreign-issuer.ncm.nokia.com",
						},
					},
				},
			},
		},
		{
			name:           "certificate-request-marked-as-failed",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionFalse,
								Reason: cmapi.CertificateRequestReasonFailed,
							},
						},
					},
				},
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
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
			provisioner:             gen.NewFakeProvisioner(),
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonFailed,
		},
		{
			name:           "certificate-request-denied",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionDenied,
								Status: cmmeta.ConditionTrue,
							},
						},
					},
				},
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
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
			provisioner:             gen.NewFakeProvisioner(),
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonDenied,
		},
		{
			name:           "certificate-request-not-approved",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
					},
				},
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
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
		},
		{
			name:           "existing-certificate-found-in-data",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionApproved,
								Status: cmmeta.ConditionTrue,
							},
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
						Certificate: []byte("existing-data"),
					},
				},
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
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
		},
		{
			name:           "cr-with-issues",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionApproved,
								Status: cmmeta.ConditionTrue,
							},
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
					},
				},
			},
			err:                     errors.New("certificate request has issues"),
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonFailed,
		},
		{
			name:           "issuer-ref-unknown-kind",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Unrecognised,
							Group: ncmv1.GroupVersion.Group,
						},
						Request: generateCSR(),
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionApproved,
								Status: cmmeta.ConditionTrue,
							},
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
					},
				},
			},
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonFailed,
		},
		{
			name:           "issuer-not-found",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						Request: generateCSR(),
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionApproved,
								Status: cmmeta.ConditionTrue,
							},
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
					},
				},
			},
			err:                     errFailedGetIssuer,
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonPending,
		},
		{
			name:           "cluster-issuer-not-found",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  ClusterIssuer,
							Group: ncmv1.GroupVersion.Group,
						},
						Request: generateCSR(),
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionApproved,
								Status: cmmeta.ConditionTrue,
							},
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
					},
				},
			},
			err:                     errFailedGetIssuer,
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonPending,
		},
		{
			name:           "issuer-not-ready",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						Request: generateCSR(),
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionApproved,
								Status: cmmeta.ConditionTrue,
							},
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
					},
				},
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionFalse,
							},
						},
					},
				},
			},
			err:                     errIssuerNotReady,
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonPending,
		},
		{
			name:           "provisioner-resource-missing",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						Request: generateCSR(),
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionApproved,
								Status: cmmeta.ConditionTrue,
							},
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
					},
				},
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
			err:                     errFailedGetProvisioner,
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonPending,
		},
		{
			name:           "certificate-object-not-found",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				&cmapi.CertificateRequest{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "cr",
					},
					Spec: cmapi.CertificateRequestSpec{
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						Request: generateCSR(),
					},
					Status: cmapi.CertificateRequestStatus{
						Conditions: []cmapi.CertificateRequestCondition{
							{
								Type:   cmapi.CertificateRequestConditionApproved,
								Status: cmmeta.ConditionTrue,
							},
							{
								Type:   cmapi.CertificateRequestConditionReady,
								Status: cmmeta.ConditionUnknown,
							},
						},
					},
				},
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
			provisioner:             gen.NewFakeProvisioner(),
			err:                     errors.New("certificate object not found"),
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonFailed,
		},
		{
			name:           "not-reachable-api-during-signing",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						PrivateKey: &cmapi.CertificatePrivateKey{
							RotationPolicy: "Always",
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSignError(errAPINotReachable)),
			err: errAPINotReachable,
			expectedResult: ctrl.Result{
				RequeueAfter: APIErrorRequeueTime,
			},
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonPending,
		},
		{
			name:           "csr-status-approved",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						PrivateKey: &cmapi.CertificatePrivateKey{
							RotationPolicy: "Always",
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSignError(provisioner.ErrCSRNotAccepted)),
			err: provisioner.ErrCSRNotAccepted,
			expectedResult: ctrl.Result{
				RequeueAfter: CSRRequeueTime,
			},
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonPending,
		},
		{
			name:           "csr-status-rejected",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						PrivateKey: &cmapi.CertificatePrivateKey{
							RotationPolicy: "Always",
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSignError(provisioner.ErrCSRRejected)),
			err:                     provisioner.ErrCSRRejected,
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonDenied,
		},
		{
			name:           "exceeded-single-csr-check-limit",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						PrivateKey: &cmapi.CertificatePrivateKey{
							RotationPolicy: "Always",
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSignError(provisioner.ErrCSRCheckLimitExceeded)),
			err:                     provisioner.ErrCSRCheckLimitExceeded,
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonDenied,
		},
		{
			name:           "csr-unexpected-error",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						PrivateKey: &cmapi.CertificatePrivateKey{
							RotationPolicy: "Always",
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSignError(errors.New("unexpected"))),
			err:                     errors.New("unexpected"),
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonPending,
		},
		{
			name:           "issuer-success-sign",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						PrivateKey: &cmapi.CertificatePrivateKey{
							RotationPolicy: "Always",
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSign([]byte("ca"), []byte("tls"), "random-id")),
			expectedConditionStatus: cmmeta.ConditionTrue,
			expectedConditionReason: cmapi.CertificateRequestReasonIssued,
		},
		{
			name:           "issuer-success-sign-not-existing-secret",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						PrivateKey: &cmapi.CertificatePrivateKey{
							RotationPolicy: "Always",
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSign([]byte("ca"), []byte("tls"), "random-id")),
			expectedConditionStatus: cmmeta.ConditionTrue,
			expectedConditionReason: cmapi.CertificateRequestReasonIssued,
		},
		{
			name:           "issuer-success-sign-manual-rotation",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSign([]byte("ca"), []byte("tls"), "random-id")),
			expectedConditionStatus: cmmeta.ConditionTrue,
			expectedConditionReason: cmapi.CertificateRequestReasonIssued,
		},
		{
			name:           "cluster-issuer-success-sign",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "", Name: "ncm-cluster-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-cluster-issuer",
								Kind:  ClusterIssuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "",
						Name:      "ncm-cluster-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: metav1.NamespaceDefault,
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: metav1.NamespaceDefault,
						Name:      "ncm-auth-secret",
					},
					Data: map[string][]byte{
						"username":    []byte("ncm-user"),
						"usrPassword": []byte("ncm-user-password"),
					},
				},
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  ClusterIssuer,
							Group: ncmv1.GroupVersion.Group,
						},
						PrivateKey: &cmapi.CertificatePrivateKey{
							RotationPolicy: "Always",
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerSign([]byte("ca"), []byte("tls"), "random-id")),
			expectedConditionStatus: cmmeta.ConditionTrue,
			expectedConditionReason: cmapi.CertificateRequestReasonIssued,
		},
		{
			name:           "not-reachable-api-during-renewal",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerRenewError(errAPINotReachable)),
			err: errAPINotReachable,
			expectedResult: ctrl.Result{
				RequeueAfter: APIErrorRequeueTime,
			},
			expectedConditionStatus: cmmeta.ConditionFalse,
			expectedConditionReason: cmapi.CertificateRequestReasonPending,
		},
		{
			name:           "issuer-success-renew",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "ncm-ns", Name: "ncm-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-issuer",
								Kind:  Issuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: "ncm-ns",
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
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
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  Issuer,
							Group: ncmv1.GroupVersion.Group,
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerRenew([]byte("ca"), []byte("tls"), "random-id")),
			expectedConditionStatus: cmmeta.ConditionTrue,
			expectedConditionReason: cmapi.CertificateRequestReasonIssued,
		},
		{
			name:           "cluster-issuer-success-renew",
			namespacedName: types.NamespacedName{Namespace: "ncm-ns", Name: "cr"},
			issuerName:     types.NamespacedName{Namespace: "", Name: "ncm-cluster-issuer"},
			objects: []client.Object{
				func() *cmapi.CertificateRequest {
					cr := &cmapi.CertificateRequest{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ncm-ns",
							Name:      "cr",
						},
						Spec: cmapi.CertificateRequestSpec{
							IssuerRef: cmmeta.ObjectReference{
								Name:  "ncm-cluster-issuer",
								Kind:  ClusterIssuer,
								Group: ncmv1.GroupVersion.Group,
							},
							Request: generateCSR(),
						},
						Status: cmapi.CertificateRequestStatus{
							Conditions: []cmapi.CertificateRequestCondition{
								{
									Type:   cmapi.CertificateRequestConditionApproved,
									Status: cmmeta.ConditionTrue,
								},
								{
									Type:   cmapi.CertificateRequestConditionReady,
									Status: cmmeta.ConditionUnknown,
								},
							},
						},
					}
					cr.Annotations = map[string]string{
						cmapi.CertificateNameKey: "ncm-cert",
					}
					return cr
				}(),
				&ncmv1.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "",
						Name:      "ncm-cluster-issuer",
					},
					Spec: ncmv1.IssuerSpec{
						CAName: "ncmCA",
						Provisioner: &ncmv1.NCMProvisioner{
							MainAPI: "https://ncm-server.local:8081",
							AuthRef: &v1.SecretReference{
								Namespace: metav1.NamespaceDefault,
								Name:      "ncm-auth-secret",
							},
							HealthCheckerInterval: metav1.Duration{Duration: time.Minute},
						},
					},
					Status: ncmv1.IssuerStatus{
						Conditions: []ncmv1.IssuerCondition{
							{
								Type:   ncmv1.IssuerConditionReady,
								Status: ncmv1.ConditionTrue,
							},
						},
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: metav1.NamespaceDefault,
						Name:      "ncm-auth-secret",
					},
					Data: map[string][]byte{
						"username":    []byte("ncm-user"),
						"usrPassword": []byte("ncm-user-password"),
					},
				},
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert",
					},
					Spec: cmapi.CertificateSpec{
						CommonName: "ncm-cert.local",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "ncm-issuer",
							Kind:  ClusterIssuer,
							Group: ncmv1.GroupVersion.Group,
						},
						SecretName: "ncm-cert-tls",
					},
					Status: cmapi.CertificateStatus{
						Revision: func() *int {
							value := 1
							return &value
						}(),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-tls",
					},
					Data: map[string][]byte{
						"tls": []byte("random-bytes"),
					},
				},
				&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ncm-ns",
						Name:      "ncm-cert-details",
					},
					Data: map[string][]byte{
						"cert-id": []byte("random-id"),
					},
				},
			},
			provisioner: gen.NewFakeProvisioner(
				gen.SetFakeProvisionerRenew([]byte("ca"), []byte("tls"), "random-id")),
			expectedConditionStatus: cmmeta.ConditionTrue,
			expectedConditionReason: cmapi.CertificateRequestReasonIssued,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			run(t, tc)
		})
	}
}
