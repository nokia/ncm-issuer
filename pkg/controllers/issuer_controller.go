/*
Copyright 2021.

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
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	ncmv1 "github.com/nokia/ncm-issuer/api/v1"
	"github.com/nokia/ncm-issuer/pkg/cfg"
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
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// IssuerReconciler reconciles a Issuer object.
type IssuerReconciler struct {
	client.Client
	Kind         string
	Scheme       *runtime.Scheme
	Clock        clock.Clock
	Recorder     record.EventRecorder
	Provisioners *provisioner.ProvisionersMap
	Log          logr.Logger
}

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := ncmv1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

//+kubebuilder:rbac:groups=certmanager.ncm.nokia.com,resources=issuers;clusterissuers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=certmanager.ncm.nokia.com,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the Issuer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("ncm-issuer", req.NamespacedName)

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, nil
	}

	if err = r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err = client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get err: %w", err)
		}
		log.Info("Issuer resource not found, ignoring...")
		return ctrl.Result{}, nil
	}

	issuerSpec, _, err := GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	NCMCfg := cfg.Initialise(issuerSpec)
	NCMCfg.InjectNamespace(GetSecretNamespace(issuer, req))
	authSecret := &core.Secret{}
	if err = r.Get(ctx, NCMCfg.AuthNamespacedName, authSecret); err != nil {
		log.Error(err, "Failed to retrieve auth secret", "namespace", NCMCfg.AuthNamespacedName.Namespace, "name", NCMCfg.AuthNamespacedName.Name)
		if apierrors.IsNotFound(err) {
			_ = r.SetStatus(ctx, issuer, ncmv1.ConditionFalse, "NotFound", "Failed to retrieve auth secret err: %v", err)
		} else {
			_ = r.SetStatus(ctx, issuer, ncmv1.ConditionFalse, "Error", "Failed to retrieve auth secret err: %v", err)
		}

		return ctrl.Result{}, err
	}

	NCMCfg.AddAuthenticationData(authSecret)
	if !reflect.DeepEqual(NCMCfg.TLSNamespacedName, types.NamespacedName{}) {
		tlsSecret := &core.Secret{}
		if err = r.Get(ctx, NCMCfg.TLSNamespacedName, tlsSecret); err != nil {
			log.Error(err, "Failed to retrieve TLS secret", "namespace", NCMCfg.TLSNamespacedName.Namespace, "name", NCMCfg.TLSNamespacedName.Name)
			if apierrors.IsNotFound(err) {
				_ = r.SetStatus(ctx, issuer, ncmv1.ConditionFalse, "NotFound", "Failed to retrieve auth secret err: %v", err)
			} else {
				_ = r.SetStatus(ctx, issuer, ncmv1.ConditionFalse, "Error", "Failed to retrieve auth secret err: %v", err)
			}

			return ctrl.Result{}, err
		}
		if err = NCMCfg.AddTLSData(tlsSecret); err != nil {
			_ = r.SetStatus(ctx, issuer, ncmv1.ConditionFalse, "Error", "Failed to add TLS secret data to config err: %v", err)
			return ctrl.Result{}, err
		}
	}

	if err = NCMCfg.Validate(); err != nil {
		log.Error(err, "Failed to validate config provided in spec")
		_ = r.SetStatus(ctx, issuer, ncmv1.ConditionFalse, "Error", "Failed to validate config provided in spec: %v", err)
		return ctrl.Result{}, err
	}

	p, err := provisioner.NewProvisioner(NCMCfg, log)
	if err != nil {
		log.Error(err, "Failed to create new provisioner")
		_ = r.SetStatus(ctx, issuer, ncmv1.ConditionFalse, "Error", "Failed to create new provisioner err: %v", err)
		return ctrl.Result{}, err
	}

	r.Provisioners.AddOrReplace(req.NamespacedName, p)

	return ctrl.Result{}, r.SetStatus(ctx, issuer, ncmv1.ConditionTrue, "Verified", "Signing CA verified and ready to sign certificates")
}

// SetCondition will set a 'condition' on the given issuer.
//   - If no condition of the same type already exists, the condition will be
//     inserted with the LastTransitionTime set to the current time.
//   - If a condition of the same type and state already exists, the condition
//     will be updated but the LastTransitionTime will not be modified.
//   - If a condition of the same type and different state already exists, the
//     condition will be updated and the LastTransitionTime set to the current
//     time.
func (r *IssuerReconciler) SetCondition(issuerStatus *ncmv1.IssuerStatus, status ncmv1.ConditionStatus, reason, message string) {
	newCondition := &ncmv1.IssuerCondition{
		Type:    ncmv1.IssuerConditionReady,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	nowTime := metav1.NewTime(r.Clock.Now())
	newCondition.LastTransitionTime = &nowTime
	for idx, cond := range issuerStatus.Conditions {
		// Skip unrelated conditions
		if cond.Type != ncmv1.IssuerConditionReady {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		} else {
			r.Log.Info("found status change for condition; setting lastTransitionTime", "condition", cond.Type, "old_status", cond.Status, "new_status", status, "time", nowTime.Time)
		}

		// Overwrite the existing condition
		issuerStatus.Conditions[idx] = *newCondition
		return
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	issuerStatus.Conditions = append(issuerStatus.Conditions, *newCondition)
	r.Log.Info("setting lastTransitionTime for issuer condition", "condition", ncmv1.IssuerConditionReady, "time", nowTime.Time)
}

func (r *IssuerReconciler) SetStatus(ctx context.Context, issuer client.Object, conditionStatus ncmv1.ConditionStatus, reason, message string, args ...interface{}) error {
	// Format the message and update the issuer variable with the new Condition
	var issuerStatus *ncmv1.IssuerStatus

	switch t := issuer.(type) {
	case *ncmv1.Issuer:
		issuerStatus = &t.Status
	case *ncmv1.ClusterIssuer:
		issuerStatus = &t.Status
	default:
		r.Log.Info("Foreign type", "type", t)
	}

	completeMessage := fmt.Sprintf(message, args...)
	r.SetCondition(issuerStatus, conditionStatus, reason, completeMessage)

	// Fire an Event to additionally inform users of the change
	eventType := core.EventTypeNormal
	if conditionStatus == ncmv1.ConditionFalse {
		eventType = core.EventTypeWarning
	}
	r.Recorder.Event(issuer, eventType, reason, completeMessage)

	// Actually update the issuer resource
	var err error
	if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
		err = utilerrors.NewAggregate([]error{err, updateErr})
		return err
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).For(issuerType).WithEventFilter(predicate.Funcs{
		DeleteFunc: func(e event.DeleteEvent) bool {
			namespacedName := types.NamespacedName{Namespace: e.Object.GetNamespace(), Name: e.Object.GetName()}
			r.Provisioners.Delete(namespacedName)
			r.Log.Info("Removing stored provisioner for deleted issuer", "namespace", namespacedName.Namespace, "name", namespacedName.Name)
			return false
		},
	}).Complete(r)
}
