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
	"errors"
	"fmt"
	"github.com/go-logr/logr"
	certmanagerv1 "github.com/nokia/ncm-issuer/api/v1"
	"github.com/nokia/ncm-issuer/pkg/pkiutil"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Kind     string
	Scheme   *runtime.Scheme
	Clock    clock.Clock
	Recorder record.EventRecorder
	Log      logr.Logger
}

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := certmanagerv1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

// NcmConfig NCM config setting from the secret
type NcmConfig struct {
	Username             string
	UsrPassword          string
	NcmSERVER            string
	CASNAME              string // cas for bcmtncm
	CASHREF              string // href for bcmtncm
	reenrollmentOnRenew  bool
	useProfileIDForRenew bool
	INSTA_CA             string // NCM root CA
	littleEndianPem      bool   // bigEndian or littleEndian: bE Cert->issuers, lE issuers->cert
	noRoot               bool   // Issuer of the Cert instead of root
	Cacert               string // tls Cacert
	Key                  string // tls client Key
	Cert                 string // tls client Cert
	InsecureSkipVerify   bool   // tls: InsecureSkipVerify
	Mtls                 bool   // Mtls is enabled
}

type NcmConfigKey struct {
	Namespace string
	Name      string
}

var (
	// NcmConfigSetting : for each certifier, NCM config setting from the secret
	NcmConfigSetting = make(map[NcmConfigKey]*NcmConfig)
)

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
	log := r.Log.WithValues("Name", req.NamespacedName)
	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognised issuer type")
		return ctrl.Result{}, err
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		log.Error(err, "Issuer not found")
		return ctrl.Result{}, err
	}
	issuerSpec, _, err := pkiutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, err
	}
	var reason, completeMessage string
	condition := certmanagerv1.ConditionFalse

	// Always attempt to update the Ready condition
	defer func() {
		_ = r.setMyCRDStatus(ctx, issuer, condition, reason, completeMessage)
	}()

	// check Spec
	invalidStr := checkIssuerSpec(issuerSpec)
	if len(invalidStr) != 0 {
		reason = "incorrect setting"
		err = errors.New(reason)
		completeMessage = fmt.Sprintf("Incorrect Spec config: %v", invalidStr)
		log.Error(err, "Incorrect Spec config setting")
		return ctrl.Result{}, err
	}

	// Fetch the ncm Secret
	secretName := types.NamespacedName{
		Name: issuerSpec.AuthSecretName,
	}
	// ignore err before GetSpecAndStatus already check issuer.(type)
	secretName.Namespace, _ = pkiutil.GetSecretNamespace(issuer, req)
	caSecret := core.Secret{}
	if err := r.Client.Get(ctx, secretName, &caSecret); err != nil {
		reason = "NotFound"
		completeMessage = fmt.Sprintf("Failed to retrieve the Auth Secret: %v", err)
		log.Error(err, "failed to retrieve Auth Secret")
		return ctrl.Result{}, err
	}

	err = checkNCMSecretData(&caSecret)
	if err != nil {
		reason = "incorrect setting"
		completeMessage = fmt.Sprintf("incorrect Auth Secret setting: %v", err)
		log.Error(err, "incorrect Auth Secret setting")
		return ctrl.Result{}, err
	}

	conf := NcmConfig{}
	populateNCMConfData(&caSecret, &conf)
	conf.NcmSERVER = issuerSpec.NcmSERVER
	// if end with '/', remove it
	conf.NcmSERVER = strings.TrimSuffix(conf.NcmSERVER, "/")
	conf.CASNAME = issuerSpec.CASNAME
	conf.CASHREF = issuerSpec.CASHREF
	conf.INSTA_CA = issuerSpec.CASNAME
	conf.littleEndianPem = issuerSpec.LittleEndian
	conf.reenrollmentOnRenew = issuerSpec.ReenrollmentOnRenew
	conf.useProfileIDForRenew = issuerSpec.UseProfileIDForRenew
	conf.noRoot = issuerSpec.NoRoot

	///////////////////////
	conf.InsecureSkipVerify = true
	if issuerSpec.TlsSecretName != "" {
		// Fetch the ncm tls Secret
		tlsConfSecret := core.Secret{}
		if err := r.Client.Get(ctx, client.ObjectKey{Namespace: secretName.Namespace, Name: issuerSpec.TlsSecretName}, &tlsConfSecret); err != nil {
			reason = "NotFound"
			completeMessage = fmt.Sprintf("Failed to retrieve tls Secret: %v", err)
			log.Error(err, "failed to retrieve tls Secret")
			return ctrl.Result{}, err
		}
		err = populateNCMTLSConfData(&tlsConfSecret, &conf)
		if err != nil {
			reason = "incorrect TLS setting"
			completeMessage = fmt.Sprintf("TLS secret config setting population is incorrect: %v", err)
			log.Error(err, "TLS secret config setting population is incorrect")
			return ctrl.Result{}, err
		}
	}
	ncmConfigKey := NcmConfigKey{secretName.Namespace, req.NamespacedName.Name}
	NcmConfigSetting[ncmConfigKey] = &conf
	reason = "Verified"
	completeMessage = "Signing CA verified and ready to issue certificates"
	condition = certmanagerv1.ConditionTrue

	return ctrl.Result{}, nil
}

// setMyCRDCondition will set a 'condition' on the given MyCRD.
// - If no condition of the same type already exists, the condition will be
//   inserted with the LastTransitionTime set to the current time.
// - If a condition of the same type and state already exists, the condition
//   will be updated but the LastTransitionTime will not be modified.
// - If a condition of the same type and different state already exists, the
//   condition will be updated and the LastTransitionTime set to the current
//   time.
func (r *IssuerReconciler) setMyCRDCondition(issuerStatus *certmanagerv1.IssuerStatus, status certmanagerv1.ConditionStatus, reason, message string) {
	newCondition := &certmanagerv1.IssuerCondition{
		Type:    certmanagerv1.IssuerConditionReady,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	nowTime := metav1.NewTime(r.Clock.Now())
	newCondition.LastTransitionTime = &nowTime
	for idx, cond := range issuerStatus.Conditions {
		// Skip unrelated conditions
		if cond.Type != certmanagerv1.IssuerConditionReady {
			continue
		}
		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		} else {
			r.Log.Info("found status change for condition; setting lastTransitionTime", "condition", certmanagerv1.IssuerConditionReady, "old_status", cond.Status, "new_status", status, "time", nowTime.Time)
		}
		// Overwrite the existing condition
		issuerStatus.Conditions[idx] = *newCondition
		return
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	issuerStatus.Conditions = append(issuerStatus.Conditions, *newCondition)
	r.Log.Info("setting lastTransitionTime for MyCRD condition", "condition", certmanagerv1.IssuerConditionReady, "time", nowTime.Time)
}

func (r *IssuerReconciler) setMyCRDStatus(ctx context.Context, issuer client.Object, conditionStatus certmanagerv1.ConditionStatus, reason, message string, args ...interface{}) error {
	// Format the message and update the myCRD variable with the new Condition
	var err error
	completeMessage := fmt.Sprintf(message, args...)
	var issuerStatus *certmanagerv1.IssuerStatus
	switch t := issuer.(type) {
	case *certmanagerv1.Issuer:
		issuerStatus = &t.Status
	case *certmanagerv1.ClusterIssuer:
		issuerStatus = &t.Status
	default:
		r.Log.Info("Foreign type ", t)
	}
	r.setMyCRDCondition(issuerStatus, conditionStatus, reason, completeMessage)

	// Fire an Event to additionally inform users of the change
	eventType := core.EventTypeNormal
	if conditionStatus == certmanagerv1.ConditionFalse {
		eventType = core.EventTypeWarning
	}
	r.Recorder.Event(issuer, eventType, reason, completeMessage)

	// Actually update the MyCRD resource
	if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
		err = utilerrors.NewAggregate([]error{err, updateErr})
	}
	return err
}

// check if all the needed data are configured correctly
func checkNCMSecretData(s *core.Secret) error {
	if s.Data == nil {
		return fmt.Errorf("no setting found in secret %s/%s", s.Namespace, s.Name)
	}
	errMsg := ""
	// check the setting
	if s.Data["username"] == nil {
		errMsg += "username is needed; "
	}
	if s.Data["usrPassword"] == nil {
		errMsg += "usrPassword is needed"
	}
	if errMsg != "" {
		return fmt.Errorf("wrong auth secret %s/%s setting, error: %s", s.Namespace, s.Name, errMsg)
	}
	return nil
}

// populate all the needed config data from the secret
func populateNCMConfData(s *core.Secret, cf *NcmConfig) {
	if s.Data["username"] != nil {
		cf.Username = string(s.Data["username"])
	}
	if s.Data["usrPassword"] != nil {
		cf.UsrPassword = string(s.Data["usrPassword"])
	}
}

// populate all the needed tls configure data from the tlsConfSecret
func populateNCMTLSConfData(tlsConfSecret *core.Secret, conf *NcmConfig) error {

	conf.Cacert = string(tlsConfSecret.Data["cacert"])

	if string(tlsConfSecret.Data["key"]) != "" {
		keyPath, err := writePemToTempFile("/tmp/clientkey", tlsConfSecret.Data["key"])
		if err != nil {
			return err
		}
		conf.Key = keyPath
	}
	if string(tlsConfSecret.Data["cert"]) != "" {
		certPath, err := writePemToTempFile("/tmp/clientcert", tlsConfSecret.Data["cert"])
		if err != nil {
			return err
		}
		conf.Cert = certPath
	}

	conf.InsecureSkipVerify = true
	if conf.Cacert != "" {
		conf.InsecureSkipVerify = false
	}

	conf.Mtls = false
	if conf.Key != "" && conf.Cert != "" {
		conf.Mtls = true
	}

	if conf.Cacert == "" && conf.Key == "" && conf.Cert == "" {
		return fmt.Errorf("no useful data cacert, key or cert in Ttls secret")
	}

	return nil
}

func checkIssuerSpec(issuerSpec *certmanagerv1.IssuerSpec) string {
	invalidStr := ""
	if len(issuerSpec.NcmSERVER) == 0 {
		invalidStr = "The ncmSERVER should not be empty. "
	}
	if len(issuerSpec.CASNAME) == 0 && len(issuerSpec.CASHREF) == 0 {
		invalidStr += "The CASNAME or CASHREF should not be empty."
	}
	return invalidStr
}

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType).
		Complete(r)
}
