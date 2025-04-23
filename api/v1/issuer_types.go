/*
Copyright 2023 Nokia

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

package v1

import (
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IssuerSpec defines the desired state of Issuer.
type IssuerSpec struct {
	// !DEPRECATED from build version 1.1.0
	// +optional
	NCMServer string `json:"ncmSERVER,omitempty"`
	// !DEPRECATED from build version 1.1.0
	// +optional
	NCMServer2 string `json:"ncmSERVER2,omitempty"`

	// CAName is a name of an existing CA in the NCM API, which
	// will be used to issue certificates.
	// +optional
	CAName string `json:"caName,omitempty"`

	// CAID is a unique identifier for existing CA in the NCM API,
	// which will be used to issue certificates.
	// +kubebuilder:validation:Pattern=[\w=_\-]+$
	// +optional
	CAID string `json:"caID,omitempty"`

	// !DEPRECATED from build version 1.1.0
	// +optional
	CAsName string `json:"CASNAME,omitempty"`
	// !DEPRECATED from build version 1.1.0
	// +optional
	CAsHREF string `json:"CASHREF,omitempty"`

	// LittleEndian specifies the byte order, setting it to true
	// will ensure that bytes are stored in LE order otherwise
	// BE order will be used.
	// +kubebuilder:default=false
	LittleEndian bool `json:"littleEndian,omitempty"`

	// !DEPRECATED from build version 1.1.0 (use PK policy in CRT kind instead)
	// +kubebuilder:default=false
	ReenrollmentOnRenew bool `json:"reenrollmentOnRenew,omitempty"`

	// UseProfileIDForRenew determines whether the profile ID should be used
	// during a certificate renewal operation
	// +kubebuilder:default=false
	UseProfileIDForRenew bool `json:"useProfileIDForRenew,omitempty"`

	// NoRoot determines whether issuing CA certificate should be included
	// in issued certificate CA field instead of root CA certificate.
	// +kubebuilder:default=false
	NoRoot bool `json:"noRoot,omitempty"`

	// ChainInSigner determines whether certificate chain should be included in
	// issued certificate CA field (intermediate certificates +
	// singing CA certificate + root CA certificate).
	// +kubebuilder:default=false
	ChainInSigner bool `json:"chainInSigner,omitempty"`

	// OnlyEECert determines whether only end-entity certificate should be included
	// in issued certificate TLS field.
	// +kubebuilder:default=false
	OnlyEECert bool `json:"onlyEECert,omitempty"`

	// ProfileID is an entity profile ID in NCM API.
	// +optional
	ProfileID string `json:"profileId,omitempty"`

	// Provisioner contains NCM provisioner configuration.
	// +optional
	Provisioner *NCMProvisioner `json:"provisioner,omitempty"`

	// !DEPRECATED from build version 1.1.0
	// +optional
	TLSSecretName string `json:"tlsSecretName"`
	// !DEPRECATED from build version 1.1.0
	// +optional
	AuthSecretName string `json:"secretName,omitempty"`
	// !DEPRECATED from build version 1.1.0
	// +optional
	AuthNamespace string `json:"authNameSpace,omitempty"`
}

// IssuerStatus defines the observed state of Issuer.
type IssuerStatus struct {
	// +optional
	Conditions []IssuerCondition `json:"conditions,omitempty"`
}

// Issuer is the Schema for the issuers API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ncmissuers
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[0].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[0].reason`
// +kubebuilder:printcolumn:name="Message",type=string,JSONPath=`.status.conditions[0].message`
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IssuerList contains a list of Issuer.
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

const IssuerKind = "Issuer"

type NCMProvisioner struct {
	// MainAPI is the URL to the main NCM API.
	MainAPI string `json:"mainAPI"`

	// BackupAPI is the URL to the backup NCM API in case of
	// the lack of connection to the main one.
	// +optional
	BackupAPI string `json:"backupAPI,omitempty"`

	// HTTPClientTimeout is a maximum amount of time that the
	// HTTP client will wait for a response from NCM API before
	// aborting the request. By default, timeout is set to 10 seconds.
	// +kubebuilder:default="10s"
	HTTPClientTimeout metav1.Duration `json:"httpClientTimeout,omitempty"`

	// HealthCheckerInterval is the time interval between each
	// NCM API health check. By default, interval is set to 1 minute.
	// +kubebuilder:default="1m"
	HealthCheckerInterval metav1.Duration `json:"healthCheckerInterval,omitempty"`

	// AuthRef is a reference to a Secret containing the credentials
	// (user and password) needed for making requests to NCM API.
	AuthRef *core.SecretReference `json:"authRef"`

	// TLSRef is a reference to a Secret containing CA bundle used to
	// verify connections to the NCM API. If the secret reference is not
	// specified and selected protocol is HTTPS, InsecureSkipVerify
	// will be used. Otherwise, TLS or mTLS connection will be used,
	// depending on provided data.
	// +optional
	TLSRef *core.SecretReference `json:"tlsRef,omitempty"`
}

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, currently ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	// +kubebuilder:validation:Enum=True;False;Unknown
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine-readable explanation for the condition's last
	// transition.
	// +optional
	Reason ReasonType `json:"reason,omitempty"`

	// Message is a human-readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// IssuerConditionType represents an Issuer condition value.
// +kubebuilder:validation:Enum=Ready
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state and able to issue certificates.
	// If the `status` of this condition is `False`, CertificateRequest controllers
	// should prevent attempts to sign certificates.
	IssuerConditionReady IssuerConditionType = "Ready"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true.
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false.
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown.
	ConditionUnknown ConditionStatus = "Unknown"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=SecretNotFound;Verified;Error
type ReasonType string

const (
	// ReasonNotFound represents the fact that secrets needed to authenticate to the NCM API do not exist in cluster.
	ReasonNotFound ReasonType = "SecretNotFound"

	// ReasonVerified represents the fact that the NCM Issuer(ClusterIssuer) are configured correctly.
	ReasonVerified ReasonType = "Verified"

	// ReasonError represents the fact that the NCM Issuer(ClusterIssuer) are configured not correctly and require user interaction.
	ReasonError ReasonType = "Error"
)

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
