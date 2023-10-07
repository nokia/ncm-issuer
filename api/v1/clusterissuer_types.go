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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterIssuer is the Schema for the clusterissuers API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=ncmclusterissuers
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[0].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[0].reason`
// +kubebuilder:printcolumn:name="Message",type=string,JSONPath=`.status.conditions[0].message`
type ClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterIssuerList contains a list of ClusterIssuer.
type ClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterIssuer `json:"items"`
}

const ClusterIssuerKind = "ClusterIssuer"

func init() {
	SchemeBuilder.Register(&ClusterIssuer{}, &ClusterIssuerList{})
}
