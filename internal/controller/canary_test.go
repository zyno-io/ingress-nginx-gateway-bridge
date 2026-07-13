// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bridgev1alpha1 "github.com/zyno-io/ingress-nginx-gateway-bridge/api/v1alpha1"
)

func TestCanaryAssignmentsUsesCorrespondingOldestPrimary(t *testing.T) {
	older := canaryTestIngress("primary", "app.example.com", "/", false)
	older.CreationTimestamp = metav1.NewTime(time.Unix(1, 0))
	newer := canaryTestIngress("primary-newer", "app.example.com", "/", false)
	newer.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
	canary := canaryTestIngress("canary", "app.example.com", "/", true)
	unmatched := canaryTestIngress("unmatched", "other.example.com", "/", true)

	assignments := canaryAssignments([]networkingv1.Ingress{newer, canary, unmatched, older})
	if got := assignments[canary.Name]; got != older.Name {
		t.Fatalf("canary primary = %q, want %q", got, older.Name)
	}
	if _, exists := assignments[unmatched.Name]; exists {
		t.Fatalf("unmatched canary was assigned to %q", assignments[unmatched.Name])
	}
}

func TestCanaryAssignmentsRequiresEveryFootprint(t *testing.T) {
	primary := canaryTestIngress("primary", "app.example.com", "/", false)
	canary := canaryTestIngress("canary", "app.example.com", "/", true)
	pathType := networkingv1.PathTypePrefix
	canary.Spec.Rules[0].HTTP.Paths = append(canary.Spec.Rules[0].HTTP.Paths, networkingv1.HTTPIngressPath{
		Path: "/missing", PathType: &pathType,
		Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
			Name: "canary", Port: networkingv1.ServiceBackendPort{Number: 8080},
		}},
	})

	if assignments := canaryAssignments([]networkingv1.Ingress{primary, canary}); len(assignments) != 0 {
		t.Fatalf("partial footprint match was accepted: %#v", assignments)
	}
}

func TestPrimaryTranslationUpdateEnqueuesAssignedCanary(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := networkingv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	primary := canaryTestIngress("primary", "app.example.com", "/", false)
	canary := canaryTestIngress("canary", "app.example.com", "/", true)
	reconciler := &IngressReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(&primary, &canary).Build(),
		Config: Config{WatchIngressWithoutClass: true},
	}
	requests := reconciler.translationToCanaries(context.Background(), &bridgev1alpha1.IngressTranslation{
		ObjectMeta: metav1.ObjectMeta{Name: primary.Name, Namespace: primary.Namespace},
	})
	if len(requests) != 1 || requests[0].Namespace != canary.Namespace || requests[0].Name != canary.Name {
		t.Fatalf("translationToCanaries() = %#v, want only %s/%s", requests, canary.Namespace, canary.Name)
	}
}

func canaryTestIngress(name, host, path string, canary bool) networkingv1.Ingress {
	pathType := networkingv1.PathTypePrefix
	annotations := map[string]string{}
	if canary {
		annotations[ingressNginxCanaryAnnotation] = "true"
	}
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps", Annotations: annotations},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: host,
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: path, PathType: &pathType,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
					Name: name, Port: networkingv1.ServiceBackendPort{Number: 8080},
				}},
			}}}},
		}}},
	}
}
