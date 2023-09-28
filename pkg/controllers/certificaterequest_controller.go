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
	crmetrics "github.com/nokia/ncm-issuer/pkg/controllers/metrics"
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
	APIErrorRequeueTime = time.Second * 30
	CSRRequeueTime      = time.Minute

	labelUnr   = "unrecognised"
	labelEnr   = "enrollment"
	labelRen   = "renewal"
	labelTrue  = "true"
	labelFalse = "false"
)

var (
	errIssuerNotReady       = errors.New("issuer is not ready yet")
	errFailedGetIssuer      = errors.New("failed to get issuer resource")
	errFailedGetProvisioner = errors.New("failed to get provisioner")
)

// CertificateRequestReconciler reconciles a CertificateRequest object.
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
	log := r.Log.WithValues("certificaterequest", req.NamespacedName)

	// Fetch the CertificateRequest resource being reconciled
	cr := &cmapi.CertificateRequest{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, err
	}

	// Update metrics after processing each certificate request
	crStartTS := time.Now()
	defer func() {
		r.updateMetrics(time.Since(crStartTS))
	}()
	crmetrics.CertificateRequestTotal.Inc()

	// Checks the CertificateRequest's issuerRef and if it does not match the
	// cert-manager group name, log a message at a debug level and stop processing.
	if cr.Spec.IssuerRef.Group != ncmv1.GroupVersion.Group {
		log.V(4).Info("Resource does not specify an issuerRef group name that we are responsible for", "group", cr.Spec.IssuerRef.Group)
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelFalse).Inc()
		return ctrl.Result{}, nil
	}

	if apiutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.V(4).Info("Certificate request has been marked as failed")
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelFalse).Inc()
		return ctrl.Result{}, nil
	}

	if apiutil.CertificateRequestIsDenied(cr) {
		log.V(4).Info("Certificate request has been denied by ncm-issuer")
		if cr.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			cr.Status.FailureTime = &nowTime
		}
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, "Certificate request has been denied by ncm-issuer")
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelFalse).Inc()
		return ctrl.Result{}, nil
	}

	if !apiutil.CertificateRequestIsApproved(cr) {
		log.V(4).Info("Certificate request has not been approved yet")
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelTrue).Inc()
		return ctrl.Result{}, nil
	}

	if len(cr.Status.Certificate) > 0 {
		log.V(4).Info("Existing certificate data found in status, skipping already completed certificate request")
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelFalse).Inc()
		return ctrl.Result{}, nil
	}

	if err := validateCertificateRequest(cr); err != nil {
		log.Error(err, "Certificate request has issues", "cr", req.NamespacedName)
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Certificate request has issues: %v", err)
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelFalse).Inc()
		return ctrl.Result{}, nil
	}

	issuerGVK := ncmv1.GroupVersion.WithKind(cr.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		log.Error(err, "Unrecognised kind. Ignoring.")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Unrecognised kind err: %v", err)
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelFalse).Inc()
		return ctrl.Result{}, nil
	}

	issuer, _ := issuerRO.(client.Object)
	issuerName := types.NamespacedName{
		Name: cr.Spec.IssuerRef.Name,
	}

	if cr.Spec.IssuerRef.Kind == ncmv1.IssuerKind {
		issuerName.Namespace = req.Namespace
	}

	if err = r.Get(ctx, issuerName, issuer); err != nil {
		log.Error(err, "Failed to get issuer")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Issuer is not existing yet")
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelTrue).Inc()
		return ctrl.Result{}, errFailedGetIssuer
	}

	issuerSpec, issuerStatus, err := GetSpecAndStatus(issuer)
	if err != nil {
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get spec and status for issuer")
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelTrue).Inc()
		return ctrl.Result{}, err
	}

	if cr.Spec.IssuerRef.Kind == ncmv1.ClusterIssuerKind {
		if issuerSpec.AuthNamespace == metav1.NamespaceNone {
			issuerSpec.AuthNamespace = metav1.NamespaceDefault
		}
	}

	if !IssuerHasCondition(*issuerStatus, ncmv1.IssuerCondition{
		Type:   ncmv1.IssuerConditionReady,
		Status: ncmv1.ConditionTrue,
	}) {
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get (cluster)issuer %s is not ready, its conditions: %s", issuerName, issuerStatus.Conditions)
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelTrue).Inc()
		return ctrl.Result{}, errIssuerNotReady
	}

	p, ok := r.Provisioners.Get(issuerName)
	if !ok {
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get provisioner for resource: %s", issuerName)
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelTrue).Inc()
		return ctrl.Result{}, errFailedGetProvisioner
	}

	crt := &cmapi.Certificate{}
	if err = r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace, Name: cr.Annotations[cmapi.CertificateNameKey]}, crt); err != nil {
		log.Error(err, "Certificate object not found")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Certificate object not found")
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelFalse).Inc()
		return ctrl.Result{}, nil
	}

	crtSecretName := cr.Annotations[cmapi.CertificateNameKey] + "-details"
	isQualified, err := r.isQualifiedForRenewal(ctx, req, crt)
	if err != nil {
		crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelTrue).Inc()
		return ctrl.Result{}, err
	}

	crtIDSecret := &core.Secret{}
	if err = r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: crtSecretName}, crtIDSecret); err != nil {
		if apierrors.IsNotFound(err) {
			crtIDSecret = nil
		} else {
			crmetrics.CertificateRequestFails.WithLabelValues(labelUnr, labelTrue).Inc()
			return ctrl.Result{}, err
		}
	}

	var ca, tls []byte
	var certID string
	if isQualified && crtIDSecret != nil && !p.PreventRenewal() {
		log.Info("Performing renewing operation", "certificate", cr.Annotations[cmapi.CertificateNameKey])
		ca, tls, certID, err = p.Renew(cr, string(crtIDSecret.Data["cert-id"]))
		if err != nil {
			if errorContains(err, "not reachable NCM API") {
				log.Error(err, "Could not established connection with NCM API")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to establish connection with NCM API err: %v", err)
				crmetrics.CertificateRequestFails.WithLabelValues(labelRen, labelTrue).Inc()
				return ctrl.Result{RequeueAfter: APIErrorRequeueTime}, nil
			}
			log.Error(err, "Failed to renew certificate")
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to renew certificate err: %v", err)
			crmetrics.CertificateRequestFails.WithLabelValues(labelRen, labelTrue).Inc()
			return ctrl.Result{}, err
		}

		crtIDSecret = GetCertIDSecret(req.Namespace, crtSecretName, certID)
		if err = r.Update(ctx, crtIDSecret); err != nil {
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to update secret err: %v", err)
			crmetrics.CertificateRequestFails.WithLabelValues(labelRen, labelTrue).Inc()
			return ctrl.Result{}, err
		}
	} else {
		log.Info("Performing signing operation", "certificate", cr.Annotations[cmapi.CertificateNameKey])
		ca, tls, certID, err = p.Sign(cr)
		if err != nil {
			switch {
			case errorContains(err, "not reachable NCM API"):
				log.Error(err, "Could not established connection with NCM API")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to establish connection with NCM API err: %v", err)
				crmetrics.CertificateRequestFails.WithLabelValues(labelEnr, labelTrue).Inc()
				return ctrl.Result{RequeueAfter: APIErrorRequeueTime}, nil
			case errors.Is(err, provisioner.ErrCSRNotAccepted):
				log.Error(err, "CSR status in NCM is not yet expected one")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "CSR in NCM has not yet been approved")
				crmetrics.CertificateRequestFails.WithLabelValues(labelEnr, labelTrue).Inc()
				return ctrl.Result{RequeueAfter: CSRRequeueTime}, nil
			case errors.Is(err, provisioner.ErrCSRRejected):
				log.Error(err, "CSR status in NCM is not expected one, further actions should be taken manually")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, "CSR has been rejected by NCM")
				crmetrics.CertificateRequestFails.WithLabelValues(labelEnr, labelFalse).Inc()
				return ctrl.Result{}, nil
			case errors.Is(err, provisioner.ErrCSRCheckLimitExceeded):
				log.Error(err, "CSR status in NCM is not expected one, further actions should be taken manually")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, "CSR has not been accepted for too long time")
				crmetrics.CertificateRequestFails.WithLabelValues(labelEnr, labelFalse).Inc()
				return ctrl.Result{}, nil
			default:
				log.Error(err, "Unexpected error during certificate signing")
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to sign certificate err: %v", err)
				crmetrics.CertificateRequestFails.WithLabelValues(labelEnr, labelTrue).Inc()
				return ctrl.Result{}, nil
			}
		}

		if crtIDSecret != nil {
			if err = r.Update(ctx, GetCertIDSecret(req.Namespace, crtSecretName, certID)); err != nil {
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to update secret err: %v", err)
				crmetrics.CertificateRequestFails.WithLabelValues(labelEnr, labelTrue).Inc()
				return ctrl.Result{}, err
			}
		} else {
			if err = r.Create(ctx, GetCertIDSecret(req.Namespace, crtSecretName, certID)); err != nil {
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to create secret err: %v", err)
				crmetrics.CertificateRequestFails.WithLabelValues(labelEnr, labelTrue).Inc()
				return ctrl.Result{}, err
			}
		}
	}

	cr.Status.CA = ca
	cr.Status.Certificate = tls
	crmetrics.CertificateRequestSuccesses.WithLabelValues(labelEnr).Inc()
	log.Info("Successfully issued certificate", "certificateName", cr.Annotations[cmapi.CertificateNameKey])
	return ctrl.Result{}, r.setStatus(ctx, cr, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Successfully issued certificate")
}

func (r *CertificateRequestReconciler) isQualifiedForRenewal(ctx context.Context, req ctrl.Request, crt *cmapi.Certificate) (bool, error) {
	// At the very beginning we should check the basic conditions that determines
	// whether the operation of certificate renewal should take place
	if crt.Status.Revision == nil || (crt.Status.Revision != nil && *crt.Status.Revision < 1) {
		return false, nil
	}
	if crt.Spec.PrivateKey != nil && crt.Spec.PrivateKey.RotationPolicy == cmapi.RotationPolicyAlways {
		return false, nil
	}

	// We also need to check if the certificate's TLS secret has been deleted,
	// which involves triggering a manual rotation of a private key
	if err := r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: crt.Spec.SecretName}, &core.Secret{}); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
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

func (r *CertificateRequestReconciler) updateMetrics(crTime time.Duration) {
	crmetrics.CertificateRequestTime.Observe(crTime.Seconds())
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
