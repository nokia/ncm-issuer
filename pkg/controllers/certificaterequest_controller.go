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
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	certmanagerv1 "github.com/nokia/ncm-issuer/api/v1"
	"github.com/nokia/ncm-issuer/pkg/ncmapi"
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
)

// CertificateRequestReconciler reconciles a MyCRD object
type CertificateRequestReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Log      logr.Logger
	Clock    clock.Clock
	Recorder record.EventRecorder
}

// ///////////////////////////////////
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
	SetStatusErrMsg = "Failed to set status"
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

	// Checks if the MyCRD resource has been marked Ready
	if !pkiutil.MyCRDHasCondition(*issuerStatus, certmanagerv1.IssuerCondition{
		Type:   certmanagerv1.IssuerConditionReady,
		Status: certmanagerv1.ConditionTrue,
	}) {
		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending,
			"Failed: (Cluster)Issuer %s is not Ready; its condition is %s", issuerName, issuerStatus.Conditions)
		if err != nil {
			log.Error(err, SetStatusErrMsg)
		}
		return ctrl.Result{}, err
	}

	// Once CRD resource is ready, the config data should be ready
	if NCMConfigMap == nil || NCMConfigMap[ncmapi.NCMConfigKey{Namespace: secretNamespace, Name: issuerName.Name}] == nil {

		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending,
			"Failed: CRD configuration %s/%s is not Ready; type,status in myCRD.Status.Conditions=%s, cfg is nil=%v", secretNamespace, issuerName.Name, issuerStatus.Conditions, NCMConfigMap)
		if err != nil {
			log.Error(err, "Fail to set certificateRequest status")
		}
		return ctrl.Result{}, err
	}

	if apiutil.CertificateRequestIsDenied(&cr) {
		log.V(4).Info("certificate request has been denied")
		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, "CSR has been denied")
		if err != nil {
			log.Error(err, SetStatusErrMsg)
		}

		return ctrl.Result{}, err
	}

	if !apiutil.CertificateRequestIsApproved(&cr) {
		log.V(4).Info("certificate request has not been approved")
		return ctrl.Result{}, nil
	}

	ncmCfg := NCMConfigMap[ncmapi.NCMConfigKey{Namespace: secretNamespace, Name: issuerName.Name}]
	ncmClient, err := ncmapi.NewClient(ncmCfg, log)
	if err != nil {
		log.Error(err, "failed to create NCM API Client")

		err = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to create NCM API Client, make sure the config is set up correctly, err=%v", err)
		if err != nil {
			log.Error(err, "failed to set certificate request status")
		}

		return ctrl.Result{}, nil
	}

	var pemChain []byte

	casResponse, err := ncmClient.GetCAs()
	if err != nil {
		log.Error(err, "failed to get CAs")

		err = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Please, check your external NCM server. Failed to get CAs: %v", err)
		if err != nil {
			log.Error(err, "failed to set certificate request status")
		}

		go r.waitAndGetCAs(ctx, req, &cr, ncmClient, log)

		return ctrl.Result{}, nil
	}

	// Finds the certificate for BCMTNCM
	wantedCA := ncmapi.CAResponse{}
	hrefRegex := regexp.MustCompile(`[\d\w=_\-]+$`)

	for _, ca := range casResponse.CAList {
		if strings.EqualFold(ca.Status, "active") {
			if ncmCfg.CASHREF != "" {
				href := hrefRegex.Find([]byte(ca.Href))

				if strings.EqualFold(string(href), ncmCfg.CASHREF) {
					wantedCA = ca
					break
				}

			} else if strings.EqualFold(ca.Name, ncmCfg.CASNAME) {
				wantedCA = ca
				break
			}
		}
	}

	if wantedCA.Href == "" {
		log.Error(err, "CA certificate has not been found. Please check provided CASHREF/CASNAME", "cashref", ncmCfg.CASHREF, "casname", ncmCfg.CASNAME)

		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "CA certificate has not been found. Please check provided CASHREF/CASNAME url=%v, CASNAME=%v; CASHREF=%v", ncmCfg.NcmSERVER+ncmapi.CAsURL, ncmCfg.CASNAME, ncmCfg.CASHREF)
		if err != nil {
			log.Error(err, SetStatusErrMsg)
		}

		return ctrl.Result{}, nil
	}

	// Finds the root CA
	instaCA := ncmapi.CAResponse{}
	lastCA := wantedCA

	for {
		log.Info("lastCA href: ", lastCA.Href)

		lastCAURLPath, err := ncmapi.GetPathFromCertURL(lastCA.Certificates["active"])
		if err != nil {
			log.Error(err, "failed to get certificate URL path needed for request")
			_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get certificate URL path needed for request: %v", err)

			return ctrl.Result{}, nil
		}

		currentCert, err := ncmClient.DownloadCertificate(lastCAURLPath)
		if err != nil {
			log.Error(err, "failed to download Certificate", "certURL", lastCA.Certificates["active"])

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate: %v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		if lastCA.Href == currentCert.IssuerCA || currentCert.IssuerCA == "" {
			break
		}

		currentCertInPEM, err := ncmClient.DownloadCertificateInPEM(lastCAURLPath)
		if err != nil {
			log.Error(err, "failed to download PEM Certificate", "certURL", lastCA.Certificates["active"])

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate: err=%v; resp=%v", err, lastCA)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		pemChain = appendPem(ncmCfg, pemChain, currentCertInPEM)

		lastCAURLPATH, err := ncmapi.GetPathFromCertURL(currentCert.IssuerCA)
		if err != nil {
			log.Error(err, "failed to get certificate URL path needed for request")
			_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get certificate URL path needed for request err=%v", err)

			return ctrl.Result{}, nil
		}

		lastCA, err = ncmClient.GetCA(lastCAURLPATH)
		if err != nil {
			log.Error(err, "failed to download CA certificate", "caURL", currentCert.IssuerCA)

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate err=%v; resp=%v", err, currentCert)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}
	}

	if ncmCfg.NoRoot {
		instaCA = wantedCA
		log.Info("Found Issuer: ", instaCA.Name)
	} else {
		instaCA = lastCA
		log.Info("Found root CA: ", instaCA.Name)
	}

	// Downloads root CA certificate
	instaCAURLPath, err := ncmapi.GetPathFromCertURL(instaCA.Certificates["active"])
	if err != nil {
		log.Error(err, "failed to get certificate URL path needed for request")
		_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get certificate URL path needed for request err=%v", err)

		return ctrl.Result{}, nil
	}

	instaCAInPEM, err := ncmClient.DownloadCertificateInPEM(instaCAURLPath)
	if err != nil {
		log.Error(err, "failed to download ROOT Certificate")
		err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate err=%v; resp=%v", err, instaCAInPEM)
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

	var enduserCAInPEM []byte
	var secretName = req.Name[:positionToSlice] + "-details"

	if crt.Status.Revision != nil {
		log.Info("Revision value fetched", "revision", crt.Status.Revision)
	} else {
		log.Info("Revision value is set to nil")
	}

	secretList, err := r.getSecretList(ctx, req)
	if err != nil {
		log.Error(err, "failed to list certificates resources")

		return ctrl.Result{}, nil
	}

	if crt.Status.Revision != nil && *crt.Status.Revision >= 1 && !ncmCfg.ReenrollmentOnRenew && pkiutil.FindIfSecretExists(secretList, secretName) && crt.Spec.PrivateKey.RotationPolicy != "Always" {
		// Gets saved certificate ID
		log.Info("A secret with cert-id will be updated...")
		secretCertID := core.Secret{}

		err := r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: secretName}, &secretCertID)
		if err != nil {
			log.Error(err, "failed to get a secret with cert-id", "secretName", secretName)
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Failed to download secret err=%v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		log.Info("A certificate href fetched", "href", string(secretCertID.Data["cert-id"]))

		certURLPath, err := ncmapi.GetPathFromCertURL(string(secretCertID.Data["cert-id"]))
		if err != nil {
			log.Error(err, "failed to get certificate URL path needed for request")
			_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get certificate URL path needed for request err=%v", err)

			return ctrl.Result{}, nil
		}

		renewCertResp, err := ncmClient.RenewCertificate(certURLPath, *cr.Spec.Duration, issuerSpec.ProfileId)
		if err != nil {
			log.Error(err, "failed to renewCertificate")

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to renewCertificate err=%v, resp=%v", err, renewCertResp)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		// Downloads the renewed certificate
		renewedCertURLPath, err := ncmapi.GetPathFromCertURL(renewCertResp.Certificate)
		if err != nil {
			log.Error(err, "failed to get certificate URL path needed for request")
			_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get certificate URL path needed for request err=%v", err)

			return ctrl.Result{}, nil
		}

		enduserCAInPEM, err := ncmClient.DownloadCertificateInPEM(renewedCertURLPath)
		if err != nil {
			log.Error(err, "failed to download Certificate", "certURL", renewCertResp.Certificate)

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate err=%v, resp=%v", err, enduserCAInPEM)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		secretCertID = pkiutil.GetSecretObject(req.Namespace, secretName, renewCertResp.Certificate)
		err = r.Client.Update(ctx, &secretCertID)
		if err != nil {
			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to update a secret err=%v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}
			return ctrl.Result{}, nil
		}
	} else {
		log.Info("A new secret with cert-id will be created...")

		csrResp, err := ncmClient.SendCSR(cr.Spec.Request, wantedCA, issuerSpec.ProfileId)
		if err != nil {
			log.Error(err, "failed send CSR")

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to send CSR err=%v, resp=%v, cr.ObjectMeta.name=%v/%v", err, csrResp, cr.ObjectMeta.Name, cr.ObjectMeta.Namespace)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		requestedCertURLPath, err := ncmapi.GetPathFromCertURL(csrResp.Href)
		if err != nil {
			log.Error(err, "failed to get certificate URL path needed for request")
			_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get certificate URL path needed for request err=%v", err)

			return ctrl.Result{}, nil
		}

		csrStatusResp, err := ncmClient.CheckCSRStatus(requestedCertURLPath)
		if err != nil {
			log.Error(err, "failed to check CSR")

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to check CSR status: %v", err)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		validCSRStatus := checkCSRStatus(csrStatusResp)
		if strings.EqualFold(csrStatusResp.Status, "pending") {
			// save context:  enqueue ( req, cr ) into job
			//
			// start new go route to do:
			// 1. check csr status
			// 2. download Certificate if it is accepted
			// 3. take 1 again if it is pending
			validCSRStatus = true

			log.Error(err, "CSR status is pending")
			_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to snd check CSR status err=%v", err)

			go r.waitAndCheckCSRStatus(ctx, req, &cr, ncmClient, requestedCertURLPath, log)

			return ctrl.Result{}, nil
		}

		if !validCSRStatus {
			log.Error(err, "Invalid CSR Status")

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Invalid Csr Status. err=%v, status=%v, cr.meta=%v", err, csrStatusResp.Status, cr.ObjectMeta)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		// Downloads certificate as csrRequestStatusResp3.Certificate
		enduserCAURLPath, err := ncmapi.GetPathFromCertURL(csrStatusResp.Certificate)
		if err != nil {
			log.Error(err, "failed to get certificate URL path needed for request")
			_ = r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to get certificate URL path needed for request err=%v", err)

			return ctrl.Result{}, nil
		}

		enduserCAInPEM, err := ncmClient.DownloadCertificateInPEM(enduserCAURLPath)
		if err != nil {
			log.Error(err, "failed to download Certificate", "certURL", csrStatusResp.Certificate)

			err := r.setStatus(ctx, &cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to download Certificate err=%v, tmp_enduser_ca_InPEM=%v", err, enduserCAInPEM)
			if err != nil {
				log.Error(err, SetStatusErrMsg)
			}

			return ctrl.Result{}, nil
		}

		// Saves cert-id to secret
		if pkiutil.FindIfSecretExists(secretList, secretName) {
			secretCertID := core.Secret{}
			secretCertID = pkiutil.GetSecretObject(req.Namespace, secretName, csrStatusResp.Certificate)
			err = r.Client.Update(ctx, &secretCertID)

		} else {
			err = r.createSecret(ctx, req.Namespace, secretName, csrStatusResp.Certificate)
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

	// Stores the signed certificate data in the status
	if ncmCfg.LittleEndianPem {
		pemChain = append(pemChain, enduserCAInPEM...)
	} else {
		pemChain = append(enduserCAInPEM, pemChain...)
	}

	// Set PEMs
	cr.Status.Certificate = pemChain
	cr.Status.CA = instaCAInPEM

	// Finally, update the status
	return ctrl.Result{}, r.setStatus(ctx, &cr, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Successfully issued certificate")
}

func (r *CertificateRequestReconciler) getSecretList(ctx context.Context, req ctrl.Request) (core.SecretList, error) {
	secretList := core.SecretList{}
	options := client.ListOptions{Namespace: req.Namespace}
	err := r.Client.List(ctx, &secretList, &options)

	return secretList, err
}

func (r *CertificateRequestReconciler) createSecret(ctx context.Context, namespace string, name string, certID string) error {
	secret := pkiutil.GetSecretObject(namespace, name, certID)
	err := r.Client.Create(ctx, &secret)

	return err
}

func appendPem(cfg *ncmapi.NCMConfig, pemChain []byte, currentPem []byte) []byte {
	if cfg.LittleEndianPem {
		pemChain = append(currentPem, pemChain...)
	} else {
		pemChain = append(pemChain, currentPem...)
	}

	return pemChain
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
	r.Log.Info(completeMessage)

	// Updates the status
	var err error
	if updateErr := r.Status().Update(ctx, cr); updateErr != nil {
		err = utilerrors.NewAggregate([]error{err, updateErr})

		return err
	}

	return nil
}

// ////////////////////////////////////

// Waits and frequently checks to see if the NCM server is responding (NCM API client tries to get CAs).
// When the server responds to a request for CAs triggers new round of reconcile
func (r *CertificateRequestReconciler) waitAndGetCAs(ctx context.Context, req ctrl.Request, cr *cmapi.CertificateRequest, client *ncmapi.Client, log logr.Logger) {
	CrPendingKey := CertificateRequestPendingKey{cr.ObjectMeta.Namespace, cr.ObjectMeta.Name}

	inFuncStr := "waitAndGetCAs"
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
			log.Error(err, "failed to retrieve CertificateRequest resource while in waitAndGetCAs. Wait no longer")
			CertificateRequestPendingList[CrPendingKey] = nil

			return
		}

		// Checks if NCM server is responding to a request
		_, err := client.GetCAs()
		if err != nil {
			log.Error(err, "failed to get CAs")
		} else {
			log.Info(inFuncStr, "time", nowTime.Time, "OK", "NCM external server is responding")

			// Updates new Certifier status change, which triggers new round of reconcile
			// Status is updated from CertificateReasonPending to CertificateRequestReasonFailed
			CertificateRequestPendingList[CrPendingKey] = nil

			_ = r.setStatus(ctx, &newcr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Now the external NCM server is ready to get CAs")

			break
		}
	}

}

// Waits and frequently checks if the CSR status is 'accepted'.
// When CSR status is accepted triggers new round fo reconcile
func (r *CertificateRequestReconciler) waitAndCheckCSRStatus(ctx context.Context, req ctrl.Request, cr *cmapi.CertificateRequest, c *ncmapi.Client, requestedCertURLPath string, log logr.Logger) {
	CrPendingKey := CertificateRequestPendingKey{cr.ObjectMeta.Namespace, cr.ObjectMeta.Name}

	inFuncStr := "waitAndCheckCSRStatus"
	if CertificateRequestPendingList != nil && CertificateRequestPendingList[CrPendingKey] != nil {
		nowTime := metav1.NewTime(r.Clock.Now())
		if CertificateRequestPendingList[CrPendingKey].InState != inFuncStr {
			log.Info("!! multiple revoke CertificateRequestReconciler but status is not waitAndCheckCSRStatus", "time", nowTime.Time)
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
			log.Error(err, "failed to retrieve CertificateRequest resource while in waitAndCheckCSRStatus. Wait no longer")

			return
		}

		// Checks the CSR status
		csrStatusResp, err := c.CheckCSRStatus(requestedCertURLPath)
		if err != nil {
			log.Error(err, "failed to check CSR status")
		} else {
			if strings.EqualFold(csrStatusResp.Status, "accepted") {
				// Continues to trigger new round CSR
				log.Info(inFuncStr, "time", nowTime.Time, "OK", "CSR status is accepted")

				// Updates new CertificateRequest status change, which trigger new round of reconcile
				// Status is updated from CertificateRequestReasonPending to CertificateRequestReasonFailed
				CertificateRequestPendingList[CrPendingKey] = nil
				_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Now CSR status is OK")

				break
			}

			if strings.EqualFold(csrStatusResp.Status, "pending") {
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

func checkCSRStatus(csrStatusResp ncmapi.CSRStatusResponse) bool {
	return strings.EqualFold(csrStatusResp.Status, "accepted")
}
