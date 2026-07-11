// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
