// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// IngressTranslationSpec identifies the source Ingress represented by this status object.
type IngressTranslationSpec struct {
	// IngressName is the name of the source Ingress in this namespace.
	IngressName string `json:"ingressName"`
}

// ResourceReference identifies a generated object.
type ResourceReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

// TranslationIssue describes a source field that was translated imperfectly or rejected.
type TranslationIssue struct {
	// Severity is Error or Warning.
	Severity string `json:"severity"`
	// Field is the Ingress field or annotation responsible for the issue.
	Field string `json:"field"`
	// Message explains the compatibility decision.
	Message string `json:"message"`
}

// IngressTranslationStatus reports the result of the latest reconciliation.
type IngressTranslationStatus struct {
	ObservedGeneration int64               `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition  `json:"conditions,omitempty"`
	GeneratedResources []ResourceReference `json:"generatedResources,omitempty"`
	Issues             []TranslationIssue  `json:"issues,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=it
// +kubebuilder:printcolumn:name="Ingress",type=string,JSONPath=`.spec.ingressName`
// +kubebuilder:printcolumn:name="Translated",type=string,JSONPath=`.status.conditions[?(@.type=="Translated")].status`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// IngressTranslation is a controller-owned status record for one source Ingress.
type IngressTranslation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngressTranslationSpec   `json:"spec"`
	Status IngressTranslationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IngressTranslationList contains IngressTranslation objects.
type IngressTranslationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IngressTranslation `json:"items"`
}
