// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bridgev1alpha1 "github.com/zyno-io/ingress-nginx-gateway-bridge/api/v1alpha1"
	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

func TestTranslationStatusLabelValue(t *testing.T) {
	tests := []struct {
		name  string
		ready metav1.ConditionStatus
		want  string
	}{
		{name: "ready", ready: metav1.ConditionTrue, want: translator.TranslationStatusReady},
		{name: "pending", ready: metav1.ConditionUnknown, want: translator.TranslationStatusPending},
		{name: "failed", ready: metav1.ConditionFalse, want: translator.TranslationStatusFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := translationStatusLabelValue(test.ready); got != test.want {
				t.Fatalf("translationStatusLabelValue(%s) = %q, want %q", test.ready, got, test.want)
			}
		})
	}
}

func TestPatchIngressTranslationLabel(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := networkingv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "apps"}}
	reconciler := &IngressReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(ing).Build()}

	var current networkingv1.Ingress
	key := client.ObjectKeyFromObject(ing)
	if err := reconciler.Get(context.Background(), key, &current); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.patchIngressTranslationLabel(
		context.Background(),
		&current,
		translator.TranslationStatusFailed,
	); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Get(context.Background(), key, &current); err != nil {
		t.Fatal(err)
	}
	if got := current.Labels[translator.TranslationStatusLabel]; got != translator.TranslationStatusFailed {
		t.Fatalf("translation label = %q, want %q", got, translator.TranslationStatusFailed)
	}
}

func TestDelegatedReadyTracksPrimaryTranslation(t *testing.T) {
	tests := []struct {
		name               string
		primaryGeneration  int64
		observedGeneration int64
		readyStatus        metav1.ConditionStatus
		readyMessage       string
		includeTranslation bool
		wantStatus         metav1.ConditionStatus
		wantReason         string
	}{
		{
			name: "ready", primaryGeneration: 2, observedGeneration: 2,
			readyStatus: metav1.ConditionTrue, includeTranslation: true,
			wantStatus: metav1.ConditionTrue, wantReason: "Delegated",
		},
		{
			name: "primary failed", primaryGeneration: 2, observedGeneration: 2,
			readyStatus: metav1.ConditionFalse, readyMessage: "route rejected", includeTranslation: true,
			wantStatus: metav1.ConditionFalse, wantReason: "DelegatedRouteNotReady",
		},
		{
			name: "stale generation", primaryGeneration: 3, observedGeneration: 2,
			readyStatus: metav1.ConditionTrue, includeTranslation: true,
			wantStatus: metav1.ConditionUnknown, wantReason: "DelegatedRoutePending",
		},
		{
			name: "translation missing", primaryGeneration: 2,
			wantStatus: metav1.ConditionUnknown, wantReason: "DelegatedRoutePending",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := networkingv1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := bridgev1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			primary := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "primary", Namespace: "apps", Generation: test.primaryGeneration},
			}
			objects := []client.Object{primary}
			if test.includeTranslation {
				translation := &bridgev1alpha1.IngressTranslation{
					ObjectMeta: metav1.ObjectMeta{Name: "primary", Namespace: "apps"},
					Status:     bridgev1alpha1.IngressTranslationStatus{ObservedGeneration: test.observedGeneration},
				}
				apimeta.SetStatusCondition(&translation.Status.Conditions, metav1.Condition{
					Type: "Ready", Status: test.readyStatus, Reason: "Test", Message: test.readyMessage,
					ObservedGeneration: test.observedGeneration,
				})
				objects = append(objects, translation)
			}
			reconciler := &IngressReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()}
			status, reason, _, err := reconciler.delegatedReady(context.Background(), "apps", "primary")
			if err != nil {
				t.Fatal(err)
			}
			if status != test.wantStatus || reason != test.wantReason {
				t.Fatalf("delegatedReady() = (%s, %q), want (%s, %q)", status, reason, test.wantStatus, test.wantReason)
			}
		})
	}
}
