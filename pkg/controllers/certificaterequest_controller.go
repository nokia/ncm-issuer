/*


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
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	"github.com/nokia/ncm-issuer/pkg/provisioner"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	GetCAsRequeueTime = time.Second * 30
	CSRRequeueTime    = time.Minute
)

var (
	errIssuerNotReady       = errors.New("issuer is not ready yet")
	errFailedGetIssuer      = errors.New("failed to get issuer resource")
	errFailedGetProvisioner = errors.New("failed to get provisioner")
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Clock        clock.Clock
	Recorder     record.EventRecorder
	Provisioners *provisioner.ProvisionersMap
	Log          logr.Logger
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile will read and validate a NCM Insta Issuer resource associated to the
// CertificateRequest resource, and it will sign the CertificateRequest with the
// provisioner in the NCM Insta Issuer.

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("CertificateRequest", req.NamespacedName)

	// Fetch the CertificateRequest resource being reconciled
	cr := &cmapi.CertificateRequest{}
	if err := r.Client.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, err
	}

	// Checks the CertificateRequest's issuerRef and if it does not match the
	// cert-manager group name, log a message at a debug level and stop processing.
	if cr.Spec.IssuerRef.Group != ncmv1.GroupVersion.Group {
		log.V(4).Info("resource does not specify an issuerRef group name that we are responsible for", "group", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	if apiutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.V(4).Info("CertificateRequest has been marked as failed")
		return ctrl.Result{}, nil
	}

	if apiutil.CertificateRequestIsDenied(cr) {
		log.V(4).Info("CertificateRequest has been denied")
		if cr.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			cr.Status.FailureTime = &nowTime
		}

		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, "CertificateRequest has been denied")
		return ctrl.Result{}, nil
	}

	if !apiutil.CertificateRequestIsApproved(cr) {
		log.V(4).Info("CertificateRequest has not been approved yet")
		return ctrl.Result{}, nil
	}

	if len(cr.Status.Certificate) > 0 {
		log.V(4).Info("existing certificate data found in status, skipping already completed CertificateRequest")
		return ctrl.Result{}, nil
	}

	if err := validateCertificateRequest(cr); err != nil {
		log.Error(err, "Certificate request has issues", "cr", req.NamespacedName)
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "certificate request has issues: %v", err)
		return ctrl.Result{}, nil
	}

	issuerGVK := ncmv1.GroupVersion.WithKind(cr.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		log.Error(err, "Unrecognised kind. Ignoring.")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "unrecognised kind err: %v", err)
		return ctrl.Result{}, nil
	}

	issuer := issuerRO.(client.Object)
	issuerName := types.NamespacedName{
		Name: cr.Spec.IssuerRef.Name,
	}

	if cr.Spec.IssuerRef.Kind == "Issuer" {
		issuerName.Namespace = req.Namespace
	}

	if err = r.Client.Get(ctx, issuerName, issuer); err != nil {
		log.Error(err, "Failed to get issuer")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "issuer is not existing yet")
		return ctrl.Result{}, errFailedGetIssuer
	}

	issuerSpec, issuerStatus, err := GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Failed to get spec and status for the issuer")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "failed to get spec and status for issuer")
		return ctrl.Result{}, nil
	}

	if cr.Spec.IssuerRef.Kind == "ClusterIssuer" {
		if issuerSpec.AuthNamespace == "" {
			issuerSpec.AuthNamespace = metav1.NamespaceDefault
		}
	}

	if !IssuerHasCondition(*issuerStatus, ncmv1.IssuerCondition{
		Type:   ncmv1.IssuerConditionReady,
		Status: ncmv1.ConditionTrue,
	}) {
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to get (cluster) issuer %s is not Ready, its condition: %s", issuerName, issuerStatus.Conditions)
		return ctrl.Result{}, errIssuerNotReady
	}

	p, ok := r.Provisioners.Get(issuerName)
	if !ok {
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to get provisioner for resource: %s", issuerName)
		return ctrl.Result{}, errFailedGetProvisioner
	}

	crt := &cmapi.Certificate{}
	if err = r.Client.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace, Name: cr.Annotations[cmapi.CertificateNameKey]}, crt); err != nil {
		log.Error(err, "Certificate object not found")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "certificate object not found")
		return ctrl.Result{}, nil
	}

	secretName := cr.Annotations[cmapi.CertificateNameKey] + "-details"

	// At the very beginning we should check the basic conditions that determines
	// whether the operation of certificate renewal should take place
	isRevision := crt.Status.Revision != nil && *crt.Status.Revision >= 1
	isPKRotationAlways := crt.Spec.PrivateKey != nil && crt.Spec.PrivateKey.RotationPolicy == "Always"
	// TODO: Provisioner is no longer an individual struct, but implements interface, thus configuration option "ReenrollmentOnRenew" should be handled somehow
	// isRenewal := isRevision && !p.NCMConfig.ReenrollmentOnRenew && !isPKRotationAlways
	isRenewal := isRevision && !isPKRotationAlways

	isSecretWithCertID := false
	secretCertID := &core.Secret{}
	if err = r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: secretName}, secretCertID); err != nil {
		if apierrors.IsNotFound(err) {
			// This means that secret needed for renewal operations does not exist,
			// and we should perform re-enrollment operation instead
			isRenewal = false
		} else {
			return ctrl.Result{}, err
		}
	} else {
		// This will prevent unnecessary checking to make sure that secret already
		// exists when creating this secret, instead we will know that we
		// have to update it
		isSecretWithCertID = true
	}

	// We also need to check if the certificate's TLS secret has been deleted,
	// which involves triggering a manual rotation of a private key
	if isRenewal {
		if err = r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: crt.Spec.SecretName}, &core.Secret{}); err != nil {
			if apierrors.IsNotFound(err) {
				isRenewal = false
			} else {
				return ctrl.Result{}, err
			}

		}
	}

	if isRenewal {
		log.Info("Renewing", "certificate", cr.Annotations[cmapi.CertificateNameKey])
		ca, tls, certID, err := p.Renew(cr, string(secretCertID.Data["cert-id"]))
		if err != nil {
			if errors.Is(err, provisioner.ErrFailedGetCAs) {
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to get CAs during renewal, requeuing...")
				return ctrl.Result{RequeueAfter: GetCAsRequeueTime}, err
			}
			log.Error(err, "failed to renew certificate")
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to renew certificate err: %v", err)
			return ctrl.Result{}, err
		}

		secretCertID = GetCertIDSecret(req.Namespace, secretName, certID)
		if err = r.Client.Update(ctx, secretCertID); err != nil {
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to update secret err: %v", err)
			return ctrl.Result{}, err
		}

		cr.Status.CA = ca
		cr.Status.Certificate = tls
	} else {
		log.Info("Singing", "certificate", cr.Annotations[cmapi.CertificateNameKey])
		ca, tls, certID, err := p.Sign(cr)
		if err != nil {
			switch {
			case errors.Is(err, provisioner.ErrFailedGetCAs):
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to get CAs during signing, requeuing...")
				return ctrl.Result{RequeueAfter: GetCAsRequeueTime}, err
			case errors.Is(err, provisioner.ErrCSRNotAccepted):
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "CSR in NCM has not yet been approved, requeing...")
				return ctrl.Result{RequeueAfter: CSRRequeueTime}, err
			case errors.Is(err, provisioner.ErrCSRRejected):
				log.Error(err, "CSR has been rejected, further actions should be taken manually")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "CSR has been rejected by NCM")
				return ctrl.Result{}, nil
			case errors.Is(err, provisioner.ErrCSRCheckLimitExceeded):
				log.Error(err, "CSR has not been accepted for too long time, further actions should be taken manually")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "CSR has not been accepted for too long time")
				return ctrl.Result{}, nil
			default:
				log.Error(err, "unexpected error during certificate signing")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to sign certificate err: %v", err)
				return ctrl.Result{}, err
			}
		}

		secretCertID = GetCertIDSecret(req.Namespace, secretName, certID)
		if isSecretWithCertID {
			if err = r.Client.Update(ctx, secretCertID); err != nil {
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to update secret err: %v", err)
				return ctrl.Result{}, err
			}
		} else {
			if err = r.Client.Create(ctx, secretCertID); err != nil {
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "failed to create secret err: %v", err)
				return ctrl.Result{}, err
			}
		}

		cr.Status.CA = ca
		cr.Status.Certificate = tls
	}

	// Finally, update the status
	return ctrl.Result{}, r.setStatus(ctx, cr, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Successfully issued certificate")
}

func (r *CertificateRequestReconciler) setStatus(ctx context.Context, cr *cmapi.CertificateRequest, status cmmeta.ConditionStatus, reason, message string, args ...interface{}) error {
	// Formats the message and updates the myCRD variable with the new Condition
	completeMessage := fmt.Sprintf(message, args...)
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, status, reason, completeMessage)

	// Fires an Event to additionally inform users of the change
	eventType := core.EventTypeNormal
	if status == cmmeta.ConditionFalse {
		eventType = core.EventTypeWarning
	}

	r.Recorder.Event(cr, eventType, reason, completeMessage)

	// Updates the status
	var err error
	if updateErr := r.Status().Update(ctx, cr); updateErr != nil {
		err = utilerrors.NewAggregate([]error{err, updateErr})

		return err
	}

	return nil
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
