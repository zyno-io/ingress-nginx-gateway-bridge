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
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bridgev1alpha1 "github.com/zyno-io/ingress-nginx-gateway-bridge/api/v1alpha1"
	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

func ptrOf[T any](v T) *T { return &v }

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

func TestGeneratedReadyWithListenerSetParent(t *testing.T) {
	newRoute := func() *gatewayv1.HTTPRoute {
		return &gatewayv1.HTTPRoute{
			TypeMeta:   metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "HTTPRoute"},
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "apps", Generation: 1},
			Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{
				Group:     ptrOf(gatewayv1.Group(gatewayv1.GroupName)),
				Kind:      ptrOf(gatewayv1.Kind("ListenerSet")),
				Name:      "public-1",
				Namespace: ptrOf(gatewayv1.Namespace("gateway")),
			}}}},
		}
	}
	newGateway := func() *gatewayv1.Gateway {
		gw := &gatewayv1.Gateway{
			TypeMeta:   metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "Gateway"},
			ObjectMeta: metav1.ObjectMeta{Name: "public", Namespace: "gateway", Generation: 1},
		}
		apimeta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
			Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue,
			Reason: "Programmed", Message: "ok", ObservedGeneration: 1,
		})
		return gw
	}
	newListenerSet := func(accepted, programmed metav1.ConditionStatus) *gatewayv1.ListenerSet {
		set := &gatewayv1.ListenerSet{
			TypeMeta:   metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "ListenerSet"},
			ObjectMeta: metav1.ObjectMeta{Name: "public-1", Namespace: "gateway", Generation: 1},
		}
		apimeta.SetStatusCondition(&set.Status.Conditions, metav1.Condition{
			Type: string(gatewayv1.ListenerSetConditionAccepted), Status: accepted,
			Reason: "Accepted", Message: "ok", ObservedGeneration: 1,
		})
		apimeta.SetStatusCondition(&set.Status.Conditions, metav1.Condition{
			Type: string(gatewayv1.ListenerSetConditionProgrammed), Status: programmed,
			Reason: "Programmed", Message: "listener set rejected", ObservedGeneration: 1,
		})
		return set
	}
	acceptedRoute := func() *gatewayv1.HTTPRoute {
		route := newRoute()
		route.Status.Parents = []gatewayv1.RouteParentStatus{{
			ParentRef:      route.Spec.ParentRefs[0],
			ControllerName: nginxGatewayController,
			Conditions: []metav1.Condition{
				{Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: 1},
				{Type: string(gatewayv1.RouteConditionResolvedRefs), Status: metav1.ConditionTrue, Reason: "ResolvedRefs", ObservedGeneration: 1},
			},
		}}
		return route
	}

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, gatewayv1.Install} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	config := Config{GatewayNamespace: "gateway", GatewayName: "public"}

	t.Run("ListenerSet and Gateway both Programmed reports Ready", func(t *testing.T) {
		reconciler := &IngressReconciler{
			Client: fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(newGateway(), newListenerSet(metav1.ConditionTrue, metav1.ConditionTrue), acceptedRoute()).Build(),
			Config: config,
		}
		status, reason, _, err := reconciler.generatedReady(context.Background(), []client.Object{newRoute()})
		if err != nil {
			t.Fatal(err)
		}
		if status != metav1.ConditionTrue {
			t.Fatalf("status = %s (%s), want True", status, reason)
		}
	})

	t.Run("ListenerSet not Programmed is reported on the Ingress", func(t *testing.T) {
		reconciler := &IngressReconciler{
			Client: fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(newGateway(), newListenerSet(metav1.ConditionTrue, metav1.ConditionFalse), acceptedRoute()).Build(),
			Config: config,
		}
		status, reason, _, err := reconciler.generatedReady(context.Background(), []client.Object{newRoute()})
		if err != nil {
			t.Fatal(err)
		}
		if status != metav1.ConditionFalse || reason != "ListenerSetNotProgrammed" {
			t.Fatalf("status = %s reason = %s, want False/ListenerSetNotProgrammed", status, reason)
		}
	})

	t.Run("route with no status for the ListenerSet parent reports RoutePending", func(t *testing.T) {
		route := newRoute()
		// The route reports status for some other, unrelated parent (same
		// generation, so it is not itself "incomplete"), but never for the
		// desired ListenerSet parentRef.
		route.Status.Parents = []gatewayv1.RouteParentStatus{{
			ParentRef:      gatewayv1.ParentReference{Name: "public"},
			ControllerName: nginxGatewayController,
			Conditions: []metav1.Condition{
				{Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue, Reason: "Accepted", ObservedGeneration: route.Generation},
				{Type: string(gatewayv1.RouteConditionResolvedRefs), Status: metav1.ConditionTrue, Reason: "ResolvedRefs", ObservedGeneration: route.Generation},
			},
		}}
		reconciler := &IngressReconciler{
			Client: fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(newGateway(), newListenerSet(metav1.ConditionTrue, metav1.ConditionTrue), route).Build(),
			Config: config,
		}
		status, reason, _, err := reconciler.generatedReady(context.Background(), []client.Object{newRoute()})
		if err != nil {
			t.Fatal(err)
		}
		if status != metav1.ConditionUnknown || reason != "RoutePending" {
			t.Fatalf("status = %s reason = %s, want Unknown/RoutePending", status, reason)
		}
	})
}
