/*
Copyright 2022.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IssuerSpec defines the desired state of Issuer
type IssuerSpec struct {
	// Define external NCM REST API URL here, as of now http/https are supported
	NCMServer string `json:"ncmSERVER"`

	// +optional
	// Secondary external NCM REST API URL in case of lack of connection to the main one
	NCMServer2 string `json:"ncmSERVER2"`

	// The name of the logical CA on the NCM instance.
	// make sure the names are unique across whole NCM installation
	CAsName string `json:"CASNAME"`

	CAsHREF              string `json:"CASHREF"`
	LittleEndian         bool   `json:"littleEndian"`
	ReenrollmentOnRenew  bool   `json:"reenrollmentOnRenew"`
	UseProfileIDForRenew bool   `json:"useProfileIDForRenew"`
	NoRoot               bool   `json:"noRoot"`
	ChainInSigner        bool   `json:"chainInSigner"`
	OnlyEECert           bool   `json:"onlyEECert"`

	// The secret which contains REST API username and password
	AuthSecretName string `json:"secretName"`

	// +optional
	// ProfileId API parameter
	ProfileId string `json:"profileId,omitempty"`

	// +optional
	// The secret which contains TLS configuration to external NCM server
	// the secret must contain 3 fields:
	// CA certificate for root CA certificate; key, cert for client CA certificate and key pair.
	//
	// for https connection,
	// if the field is empty, InsecureSkipVerify is used.
	// if the field is with CA certificate only, CA certificate is used.
	// if the field are with CA certificate, key, cert and mTLS is used.
	TLSSecretName string `json:"tlsSecretName"`

	// +optional
	AuthNamespace string `json:"authNameSpace,omitempty"`
}

// IssuerStatus defines the observed state of Issuer
type IssuerStatus struct {
	// +optional
	Conditions []IssuerCondition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Issuer is the Schema for the issuers API
// +kubebuilder:resource:shortName=external-issuer
// +kubebuilder:printcolumn:name="READY",type=string,JSONPath=`.status.conditions[0].status`
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
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
	Reason string `json:"reason,omitempty"`

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
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
