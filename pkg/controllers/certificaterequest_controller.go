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
	certmanagerv1 "cm/api/v1"
	"cm/pkg/pkiutil"
	"context"
	"fmt"
	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"regexp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
	"time"
)

// CertificateRequestReconciler reconciles a MyCRD object
type CertificateRequestReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Log      logr.Logger
	Clock    clock.Clock
	Recorder record.EventRecorder
}

/////////////////////////////////////
var (
	// CertificateRequestPendingList CertificateRequest pending list, only one should be queued
	CertificateRequestPendingList = make(map[CertificateRequestPendingKey]*CertificateRequestPendingState)
)

// CertificateRequestPendingKey key to CSRPendingList
type CertificateRequestPendingKey struct {
	UsedNamespace string
	UserCrName    string
}

// CertificateRequestPendingState Certificate Request Pending State
type CertificateRequestPendingState struct {
	InState string
}

const (
	SleepTime       = 20000 // in time.Millisecond, 20s
	SetStatusErrMsg = "Fail to set status"
)

/////////////////////////////////////

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile will read and validate a NCM Insta Issuer resource associated to the
// CertificateRequest resource, and it will sign the CertificateRequest with the
// provisioner in the NCM Insta Issuer.

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("CertificateRequest", req.NamespacedName)

	// Fetch the CertificateRequest resource being reconciled
	cr := cmapi.CertificateRequest{}

	if err := r.Client.Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check the CertificateRequest's issuerRef and if it does not match the
	// cert-manager group name, log a message at a debug level and stop processing.
	if cr.Spec.IssuerRef.Group != certmanagerv1.GroupVersion.Group {
		log.V(4).Info("resource does not specify an issuerRef group name that we are responsible for", "group", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// If the certificate data is already set then we skip this request as it
	// has already been completed in the past.
	if len(cr.Status.Certificate) > 0 {
		log.V(4).Info("existing certificate data found in status, skipping already completed CertificateRequest")
		return ctrl.Result{}, nil
	}

	// Unrecognised issuerRef.Kind
	issuerGVK := certmanagerv1.GroupVersion.WithKind(cr.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		log.Error(err, "Unrecognised kind. Ignoring.")
		return ctrl.Result{}, nil
	}

	// get Issuer or ClusterIssuer resource
	issuer := issuerRO.(client.Object)
	var secretNamespace string

	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: cr.Spec.IssuerRef.Name,
	}
	if cr.Spec.IssuerRef.Kind == "Issuer" {
		issuerName.Namespace = req.Namespace
		secretNamespace = req.Namespace
	}
	// Get the Issuer or ClusterIssuer
	if err := r.Client.Get(ctx, issuerName, issuer); err != nil {
		_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Issuer is not existing yet")
		log.Error(err, "fail to get "+issuerName.Name)
		return ctrl.Result{}, nil
	}
	issuerSpec, issuerStatus, err := pkiutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Fail to get spec and status for the issuer")
		return ctrl.Result{}, nil
	}
	if cr.Spec.IssuerRef.Kind == "ClusterIssuer" {
		if issuerSpec.AuthNamespace == "" {
			issuerSpec.AuthNamespace = "default"
		}
		secretNamespace = issuerSpec.AuthNamespace
	}

	// Check if the MyCRD resource has been marked Ready
	if !pkiutil.MyCRDHasCondition(*issuerStatus, certmanagerv1.IssuerCondition{
		Type:   certmanagerv1.IssuerConditionReady,
		Status: certmanagerv1.ConditionTrue,
	}) {
		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending,
			"Failed: (Cluster)Issuer %s is not Ready; its condition is %s", issuerName, issuerStatus.Conditions)
		if err != nil {
			log.Error(err, SetStatusErrMsg)
		}
		return ctrl.Result{}, nil
	}

	// once CRD resource is ready, the config data should be ready
	if NcmConfigSetting == nil || NcmConfigSetting[NcmConfigKey{secretNamespace, issuerName.Name}] == nil {

		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending,
			"Failed: CRD configuration %s/%s is not Ready; type,status in myCRD.Status.Conditions=%s, conf is nil=%v", secretNamespace, issuerName.Name, issuerStatus.Conditions, NcmConfigSetting)
		if err != nil {
			log.Error(err, "Fail to set certificateRequest status")
		}
		return ctrl.Result{}, nil
	}

	if apiutil.CertificateRequestIsDenied(&cr) {
		log.V(4).Info("certificate request has been denied")
		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, "CSR has been denied")
		if err != nil {
			log.Error(err, SetStatusErrMsg)
		}

		return ctrl.Result{}, nil
	}

	if !apiutil.CertificateRequestIsApproved(&cr) {
		log.V(4).Info("certificate request has not been approved")
		return ctrl.Result{}, nil
	}

	ncmConfigOne := NcmConfigSetting[NcmConfigKey{secretNamespace, issuerName.Name}]
	var pemChain []byte

	// the http interface to NCM (netguard certificate manager)
	// to find CA with the external NCM server
	_, err, casInfoTotal := findCa(ncmConfigOne, log)
	if err != nil {
		log.Error(err, "failed find CA")
		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Check your external NCM server. Failed to find ca: %v", err)
		if err != nil {
			log.Error(err, "Fail to set certificateRequest status")
		}
		go r.waitCheckFindca(ctx, req, &cr, ncmConfigOne, log)
		return ctrl.Result{}, nil
	}

	// find the certificate for bcmtncm
	casOneNcm := CasOneType{}

	hrefRegex := regexp.MustCompile(`[\d\w=_\-]+$`)

	for _, cas1 := range casInfoTotal.CasoneList {
		if strings.EqualFold(cas1.Status, "active") {
			if ncmConfigOne.CASHREF != "" {
				href := hrefRegex.Find([]byte(cas1.Href))

				if strings.EqualFold(string(href), ncmConfigOne.CASHREF) {
					casOneNcm = cas1
					break
				}
			} else if strings.EqualFold(cas1.Name, ncmConfigOne.CASNAME) {
				casOneNcm = cas1
				break
			}
		}
	}

	if casOneNcm.Href == "" {
		log.Error(err, "CA certificate has not been found. Please check provided CASHREF/CASNAME", "cashref", ncmConfigOne.CASHREF, "casname", ncmConfigOne.CASNAME)
		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "CA certificate has not been found. Please check provided CASHREF/CASNAME url=%v, CASNAME=%v; CASHREF=%v", ncmConfigOne.NcmSERVER+findCaURL, ncmConfigOne.CASNAME, ncmConfigOne.CASHREF)
		if err != nil {
			log.Error(err, SetStatusErrMsg)
		}
		return ctrl.Result{}, nil
	}
	// find the root CA
	casoneInstaCa := CasOneType{}
	lastCa := casOneNcm

	for {
		log.Info(fmt.Sprintf("lastCa href: %s", lastCa.Href))
		_, err, currentCert := downloadCertificate(lastCa.Certificates["active"], ncmConfigOne, log)

		if err != nil {
			log.Error(err, "Failed to download Certificate", "certURL", lastCa.Certificates["active"])
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate: %v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}

		if lastCa.Href == currentCert.IssuerCa || currentCert.IssuerCa == "" {
			break
		}
		_, err, currentPem := downloadCertificateInPEM(lastCa.Certificates["active"], ncmConfigOne, log)
		if err != nil {
			log.Error(err, "failed to download PEM Certificate", "certURL", lastCa.Certificates["active"])
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate: err=%v; resp=%v", err, lastCa)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}
		pemChain = appendPem(ncmConfigOne, pemChain, currentPem)

		_, err, lastCa = findOneCa(currentCert.IssuerCa, ncmConfigOne, log)
		if err != nil {
			log.Error(err, "failed to download CA certificate", "caURL", currentCert.IssuerCa)
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate: err=%v; resp=%v", err, currentCert)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}
	}

	if ncmConfigOne.noRoot {
		casoneInstaCa = casOneNcm
		log.Info(fmt.Sprintf("Found Issuer: %s", casoneInstaCa.Name))
	} else {
		casoneInstaCa = lastCa
		log.Info(fmt.Sprintf("Found root CA: %s", casoneInstaCa.Name))
	}
	// download rootCA certificate
	_, err, InstaCaInpem := downloadCertificateInPEM(casoneInstaCa.Certificates["active"], ncmConfigOne, log)
	if err != nil {
		log.Error(err, "failed to download ROOT Certificate")
		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate: err=%v; resp=%v", err, InstaCaInpem)
		if err != nil {
			log.Error(err, SetStatusErrMsg)
		}
		return ctrl.Result{}, nil
	}

	crt := cmapi.Certificate{}

	positionToSlice := strings.LastIndex(req.Name, "-")
	if err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace, Name: req.Name[:positionToSlice]}, &crt); err != nil {
		log.Error(err, "Certificate object not found!")
		return ctrl.Result{}, nil
	}

	var enduserCaInpem []byte
	var secretName = req.Name[:positionToSlice] + "-details"

	if crt.Status.Revision != nil {
		log.Info("Revision value fetched", "revision", crt.Status.Revision)
	} else {
		log.Info("Revision value is set to nil")
	}

	secretList, err := r.getSecretList(ctx, req, err)
	if err != nil {
		log.Error(err, "failed to list certificates resources")
		return ctrl.Result{}, nil
	}

	if crt.Status.Revision != nil && *crt.Status.Revision >= 1 && ncmConfigOne.reenrollmentOnRenew != true && pkiutil.FindIfSecretExists(secretList, secretName) && crt.Spec.PrivateKey.RotationPolicy != "Always" {
		// Get saved certificate id
		log.Info("A secret with cert-id will be updated...")
		secretCertID := core.Secret{}
		err := r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: secretName}, &secretCertID)
		if err != nil {
			log.Error(err, "failed to get a secret with cert-id", "secretName", secretName)
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Failed to download secret: %v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}
		log.Info("A certificate href fetched", "href", string(secretCertID.Data["cert-id"]))

		_, err, renewCertificateResp := renewCertificate(*cr.Spec.Duration, string(secretCertID.Data["cert-id"]), issuerSpec.ProfileId, ncmConfigOne, log)

		if err != nil {
			log.Error(err, "failed to renewCertificate")
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to renewCertificate: %v, resp=%v", err, renewCertificateResp)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}

		// download the renewed certificate
		_, err, enduserCaInpem = downloadCertificateInPEM(renewCertificateResp.Certificate, ncmConfigOne, log)

		if err != nil {
			log.Error(err, "failed to download Certificate", "certURL", renewCertificateResp.Certificate)
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate: %v, resp=%v", err, enduserCaInpem)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}
		secretCertID = pkiutil.GetSecretObject(req.Namespace, secretName, renewCertificateResp.Certificate)
		err = r.Client.Update(ctx, &secretCertID)

		if err != nil {
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to update a secret: %v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}
	} else {
		log.Info("A new secret with cert-id will be created...")

		_, err, csrResp2 := sendCSRRequest(cr.Spec.Request, casOneNcm, ncmConfigOne, log, issuerSpec.ProfileId)
		if err != nil {
			log.Error(err, "failed send CSR request")
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to send CSR request: %v, resp=%v, cr.ObjectMeta.name=%v/%v", err, csrResp2, cr.ObjectMeta.Name, cr.ObjectMeta.Namespace)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}

		_, err, csrRequestStatusResp3 := checkCsrRequestStatus(csrResp2.Href, ncmConfigOne, log)
		if err != nil {
			log.Error(err, "failed to check CSR request csrRequestStatusResp3")
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to check CSR status: %v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}

		validCsrStatus := CheckCSRStatusResp(csrRequestStatusResp3)

		if strings.EqualFold(csrRequestStatusResp3.Status, "pending") {
			// save context:  enqueue ( req, cr ) into job
			//
			// start new go route to do:
			// 1. check csr status
			// 2. download Certificate if it is accepted
			// 3. take 1 again if it is pending
			validCsrStatus = true

			log.Error(err, "CSR request status is pending")
			_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to snd check CSR status: %v", err)

			go r.waitCheckCSRrequestStatus(ctx, req, &cr, ncmConfigOne, log, &csrResp2)

			return ctrl.Result{}, nil
		}

		if validCsrStatus == false {
			log.Error(err, "Invalid CSR Status")
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Invalid Csr Status. err=%v, status=%v, cr.meta=%v", err, csrRequestStatusResp3.Status, cr.ObjectMeta)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}

		// download certificate ascsrRequestStatusResp3.Certificate
		_, err, enduserCaInpem = downloadCertificateInPEM(csrRequestStatusResp3.Certificate, ncmConfigOne, log)
		if err != nil {
			log.Error(err, "failed to download Certificate", "certURL", csrRequestStatusResp3.Certificate)
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate: %v, tmp_enduser_ca_InPEM=%v", err, enduserCaInpem)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}

		// save cert-id to secret
		if pkiutil.FindIfSecretExists(secretList, secretName) {
			secretCertID := core.Secret{}
			secretCertID = pkiutil.GetSecretObject(req.Namespace, secretName, csrRequestStatusResp3.Certificate)
			err = r.Client.Update(ctx, &secretCertID)

		} else {
			err = r.createSecret(ctx, req.Namespace, secretName, csrRequestStatusResp3.Certificate)
		}
		if err != nil {
			log.Error(err, "failed to create/update a secret with cert-id", "secretName", secretName)
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to create/update secret: %v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}
	}
	log.Info("Storing PEM...")
	// Store the signed certificate data in the status
	if ncmConfigOne.littleEndianPem {
		pemChain = append(pemChain, enduserCaInpem...)
	} else {
		pemChain = append(enduserCaInpem, pemChain...)
	}
	// set pems
	cr.Status.Certificate = pemChain
	cr.Status.CA = InstaCaInpem

	// Finally, update the status
	return ctrl.Result{}, r.setStatus(ctx, &cr, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Successfully issued certificate")
}

func (r *CertificateRequestReconciler) getSecretList(ctx context.Context, req ctrl.Request, err error) (core.SecretList, error) {
	secretList := core.SecretList{}
	options := client.ListOptions{Namespace: req.Namespace}
	err = r.Client.List(ctx, &secretList, &options)
	return secretList, err
}

func (r *CertificateRequestReconciler) createSecret(ctx context.Context, namespace string, name string, certID string) error {
	secret := pkiutil.GetSecretObject(namespace, name, certID)
	err := r.Client.Create(ctx, &secret)

	return err
}

func appendPem(ncmConfigOne *NcmConfig, pemChain []byte, currentPem []byte) []byte {
	if ncmConfigOne.littleEndianPem {
		pemChain = append(currentPem, pemChain...)
	} else {
		pemChain = append(pemChain, currentPem...)
	}
	return pemChain
}

func (r *CertificateRequestReconciler) setStatus(ctx context.Context, cr *cmapi.CertificateRequest, status cmmeta.ConditionStatus, reason, message string, args ...interface{}) error {
	// Format the message and update the myCRD variable with the new Condition
	completeMessage := fmt.Sprintf(message, args...)
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, status, reason, completeMessage)

	// Fire an Event to additionally inform users of the change
	eventType := core.EventTypeNormal
	if status == cmmeta.ConditionFalse {
		eventType = core.EventTypeWarning
	}
	r.Recorder.Event(cr, eventType, reason, completeMessage)
	r.Log.Info(completeMessage)

	// updating the status
	var err error
	if updateErr := r.Status().Update(ctx, cr); updateErr != nil {
		err = utilerrors.NewAggregate([]error{err, updateErr})
		return err
	}
	return nil
}

//////////////////////////////////////
// wait and frequently check if the NCM external server is ready
// when it is ready, trigger new round of reconcile
func (r *CertificateRequestReconciler) waitCheckFindca(ctx context.Context, req ctrl.Request, cr *cmapi.CertificateRequest, ncmConfigOne *NcmConfig, log logr.Logger) {
	CrPendingKey := CertificateRequestPendingKey{cr.ObjectMeta.Namespace, cr.ObjectMeta.Name}

	inFuncStr := "waitCheckFindca"
	if CertificateRequestPendingList != nil && CertificateRequestPendingList[CrPendingKey] != nil {
		nowTime := metav1.NewTime(r.Clock.Now())

		if CertificateRequestPendingList[CrPendingKey].InState != inFuncStr {
			log.Info("!! multiple revoke CertificateRequestReconciler", "but status is", inFuncStr, "time", nowTime.Time)
		}
		// multiple revoke CertificateRequestReconciler, do nothing
		log.Info("multiple revoke CertificateRequestReconciler, do nothing ", "time", nowTime.Time)
		return
	}

	crPendingSt := CertificateRequestPendingState{}
	crPendingSt.InState = inFuncStr

	CertificateRequestPendingList[CrPendingKey] = &crPendingSt

	for {
		time.Sleep(SleepTime * time.Millisecond) // 20s

		nowTime := metav1.NewTime(r.Clock.Now())
		log.Info(inFuncStr, "time", nowTime.Time)

		// Fetch the CertificateRequest resource that was being synced
		newcr := cmapi.CertificateRequest{}
		if err := r.Client.Get(ctx, req.NamespacedName, &newcr); err != nil {
			log.Error(err, "failed to retrieve CertificateRequest resource while in waitCheckFindca, take no more waiting")
			CertificateRequestPendingList[CrPendingKey] = nil
			return
		}

		// check to find CA with the external NCM server
		if _, err, _ := findCa(ncmConfigOne, log); err != nil {
			log.Error(err, "failed find CA")
		} else {
			log.Info(inFuncStr, "time", nowTime.Time, "OK", "find the NCM external server ")

			// udpate new Certifier status change, which trigger new round of reconcile
			// status is updated from CertificateRequestReasonPending to CertificateRequestReasonFailed
			CertificateRequestPendingList[CrPendingKey] = nil
			_ = r.setStatus(ctx, &newcr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Now the external NCM server is OK to find.")

			break
		}
	}

}

// wait and frequently check if the check CSRrequest Status is 'accepted'
// when it is ready, trigger new round of reconcile
func (r *CertificateRequestReconciler) waitCheckCSRrequestStatus(ctx context.Context, req ctrl.Request, cr *cmapi.CertificateRequest, ncmConfigOne *NcmConfig, log logr.Logger, csrResp2 *CsrRespType) {
	CrPendingKey := CertificateRequestPendingKey{cr.ObjectMeta.Namespace, cr.ObjectMeta.Name}

	inFuncStr := "waitCheckCSRrequestStatus"
	if CertificateRequestPendingList != nil && CertificateRequestPendingList[CrPendingKey] != nil {
		nowTime := metav1.NewTime(r.Clock.Now())

		if CertificateRequestPendingList[CrPendingKey].InState != inFuncStr {
			log.Info("!! multiple revoke CertificateRequestReconciler but status is not waitCheckCSRrequestStatus", "time", nowTime.Time)
		}
		// multiple revoke CertificateRequestReconciler, do nothing
		log.Info("multiple revoke CertificateRequestReconciler, do nothing ", "time", nowTime.Time)
		return
	}

	crPendingSt := CertificateRequestPendingState{}
	crPendingSt.InState = inFuncStr

	CertificateRequestPendingList[CrPendingKey] = &crPendingSt

	for {
		time.Sleep(SleepTime * time.Millisecond) // 20s

		nowTime := metav1.NewTime(r.Clock.Now())
		log.Info(inFuncStr, "time", nowTime.Time)

		// Fetch the CertificateRequest resource that was being synced
		newcr := cmapi.CertificateRequest{}
		if err := r.Client.Get(ctx, req.NamespacedName, &newcr); err != nil {
			CertificateRequestPendingList[CrPendingKey] = nil
			log.Error(err, "failed to retrieve CertificateRequest resource while in waitCheckCSRrequestStatus, take no more waiting")
			return
		}

		// check to check CSRrequest Status
		_, err, csrRequestStatusResp3 := checkCsrRequestStatus(csrResp2.Href, ncmConfigOne, log)
		if err != nil {
			log.Info("failed to check CSR request csrRequestStatusResp3")
		} else {
			if strings.EqualFold(csrRequestStatusResp3.Status, "accepted") {
				// continue to trigger new round CSR
				log.Info(inFuncStr, "time", nowTime.Time, "OK", "CSR request status is accepted")

				// update new CertificateRequest status change, which trigger new round of reconcile
				// status is updated from CertificateRequestReasonPending to CertificateRequestReasonFailed
				CertificateRequestPendingList[CrPendingKey] = nil
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Now CSR request status is OK")
				break
			}
			// testCntCheckCSRrequestStatus++
			if strings.EqualFold(csrRequestStatusResp3.Status, "pending") {
				log.Info("CSR request status is still pending")
			}
		}
	}
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}

func CheckCSRStatusResp(csrRequestStatusResp3 CsrRequestStatusRespType) bool {
	validCsrStatus := false

	if strings.EqualFold(csrRequestStatusResp3.Status, "accepted") {
		validCsrStatus = true
	}
	return validCsrStatus
}
