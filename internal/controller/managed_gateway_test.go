// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

func newManagedGatewayScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, gatewayv1.Install} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func managedTestIngress(namespace, name, secret, host string) *networkingv1.Ingress {
	pathType := networkingv1.PathTypePrefix
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: secret}},
			Rules: []networkingv1.IngressRule{{
				Host: host,
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						Path: "/", PathType: &pathType,
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: "app", Port: networkingv1.ServiceBackendPort{Number: 8080},
						}},
					}},
				}},
			}},
		},
	}
}

func baseManagedConfig() Config {
	return Config{
		GatewayNamespace: "gateway", GatewayName: "public", GatewayClassName: "nginx",
		HTTPSectionName: "http", HTTPSSectionName: "https",
		ManageGateway: true, WatchIngressWithoutClass: true, ListenerSetsAvailable: true,
	}
}

func TestManagedGatewayOverflowThenShrinkPrunesListenerSet(t *testing.T) {
	scheme := newManagedGatewayScheme(t)
	objects := make([]client.Object, 0, 70)
	for i := 1; i <= 70; i++ {
		host := fmt.Sprintf("h%02d.example.com", i)
		objects = append(objects, managedTestIngress("apps", fmt.Sprintf("app-%02d", i), "shared-tls", host))
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	reconciler := &IngressReconciler{Client: fakeClient, Config: baseManagedConfig()}
	ctx := context.Background()

	if _, err := reconciler.reconcileManagedGateway(ctx); err != nil {
		t.Fatalf("reconcileManagedGateway: %v", err)
	}

	var sets gatewayv1.ListenerSetList
	if err := reconciler.List(ctx, &sets, client.InNamespace("gateway")); err != nil {
		t.Fatal(err)
	}
	if len(sets.Items) != 1 {
		t.Fatalf("ListenerSets = %d, want 1", len(sets.Items))
	}
	if got := len(sets.Items[0].Spec.Listeners); got != 7 {
		t.Fatalf("overflow set listeners = %d, want 7 (70 - 63)", got)
	}

	var gateway gatewayv1.Gateway
	if err := reconciler.Get(ctx, types.NamespacedName{Namespace: "gateway", Name: "public"}, &gateway); err != nil {
		t.Fatal(err)
	}
	if gateway.Spec.AllowedListeners == nil {
		t.Fatal("expected AllowedListeners while an overflow ListenerSet exists")
	}

	var grants gatewayv1.ReferenceGrantList
	if err := reconciler.List(ctx, &grants, client.InNamespace("apps")); err != nil {
		t.Fatal(err)
	}
	if len(grants.Items) != 1 {
		t.Fatalf("grants = %d, want 1 (shared cross-namespace Secret)", len(grants.Items))
	}
	if got := len(grants.Items[0].Spec.From); got != 2 {
		t.Fatalf("grant From entries = %d, want Gateway + ListenerSet", got)
	}

	// Delete exactly the Ingresses whose hosts overflowed into the ListenerSet.
	for i := 64; i <= 70; i++ {
		host := fmt.Sprintf("h%02d.example.com", i)
		ing := managedTestIngress("apps", fmt.Sprintf("app-%02d", i), "shared-tls", host)
		if err := reconciler.Delete(ctx, ing); err != nil {
			t.Fatalf("delete %s: %v", ing.Name, err)
		}
	}
	if _, err := reconciler.reconcileManagedGateway(ctx); err != nil {
		t.Fatalf("reconcileManagedGateway (shrink): %v", err)
	}
	if err := reconciler.List(ctx, &sets, client.InNamespace("gateway")); err != nil {
		t.Fatal(err)
	}
	if len(sets.Items) != 0 {
		t.Fatalf("ListenerSets = %d, want 0 after removing all overflow hosts", len(sets.Items))
	}
	if err := reconciler.Get(ctx, types.NamespacedName{Namespace: "gateway", Name: "public"}, &gateway); err != nil {
		t.Fatal(err)
	}
	if gateway.Spec.AllowedListeners != nil {
		t.Fatal("expected AllowedListeners to clear once no ListenerSets remain")
	}
}

func TestManagedGatewayBootstrapsPlacementFromCluster(t *testing.T) {
	scheme := newManagedGatewayScheme(t)
	certRefNamespace := gatewayv1.Namespace("apps")
	mode := gatewayv1.TLSModeTerminate
	hostname := gatewayv1.Hostname("a.example.com")
	existingSet := &gatewayv1.ListenerSet{
		TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "ListenerSet"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      translator.ManagedListenerSetName("public", 1),
			Namespace: "gateway",
			Labels: map[string]string{
				translator.ManagedByLabel:        translator.ControllerName,
				translator.GatewayLabel:          translator.GatewayLabelValue("gateway", "public"),
				translator.ListenerSetIndexLabel: "1",
			},
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "public"},
			Listeners: []gatewayv1.ListenerEntry{{
				Name: "https-a", Hostname: &hostname, Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
				TLS: &gatewayv1.ListenerTLSConfig{Mode: &mode, CertificateRefs: []gatewayv1.SecretObjectReference{{
					Name: "a-tls", Namespace: &certRefNamespace,
				}}},
			}},
		},
	}
	managedGateway := &gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "Gateway"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "public", Namespace: "gateway",
			Labels: map[string]string{
				translator.ManagedByLabel: translator.ControllerName,
				translator.GatewayLabel:   translator.GatewayLabelValue("gateway", "public"),
			},
		},
		Spec: gatewayv1.GatewaySpec{GatewayClassName: "nginx", Listeners: []gatewayv1.Listener{{
			Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
		}}},
	}
	ing := managedTestIngress("apps", "app", "a-tls", "a.example.com")
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ing).Build()
	reconciler := &IngressReconciler{Client: fakeClient, Config: baseManagedConfig()}
	ctx := context.Background()

	// Seed the Gateway and ListenerSet through the same apply path production
	// uses, as if an earlier run of this controller had created them, so a
	// subsequent apply from the same field manager does not conflict.
	if err := reconciler.apply(ctx, managedGateway); err != nil {
		t.Fatalf("seed Gateway: %v", err)
	}
	if err := reconciler.apply(ctx, existingSet); err != nil {
		t.Fatalf("seed ListenerSet: %v", err)
	}

	if _, err := reconciler.reconcileManagedGateway(ctx); err != nil {
		t.Fatalf("reconcileManagedGateway: %v", err)
	}
	placement, ok := reconciler.listenerPlacements["a.example.com"]
	if !ok || placement.ListenerSet != 1 {
		t.Fatalf("a.example.com placement = %#v, want to stay in ListenerSet 1 (bootstrapped from cluster)", placement)
	}
}

func TestManagedGatewayCollapsesAcrossNamespaces(t *testing.T) {
	scheme := newManagedGatewayScheme(t)
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cert, key := generateControllerTestCertificate(t, "*.s24.dev")
	alphaSecret := transformedSecret(t, "alpha", "wild", cert, key)
	betaSecret := transformedSecret(t, "beta", "wild", cert, key) // identical certificate, different namespace

	alphaIng := managedTestIngress("alpha", "app", "wild", "a.s24.dev")
	betaIng := managedTestIngress("beta", "app", "wild", "b.s24.dev")

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(alphaSecret, betaSecret, alphaIng, betaIng).Build()
	config := baseManagedConfig()
	config.ListenerSetsAvailable = false
	config.CollapseWildcardCertificates = true
	reconciler := &IngressReconciler{Client: fakeClient, Config: config}

	plan, err := reconciler.reconcileManagedGateway(context.Background())
	if err != nil {
		t.Fatalf("reconcileManagedGateway: %v", err)
	}
	if len(plan.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", plan.Issues)
	}
	httpsListeners := 0
	for _, l := range plan.Gateway.Spec.Listeners {
		if l.Protocol == gatewayv1.HTTPSProtocolType {
			httpsListeners++
		}
	}
	if httpsListeners != 1 {
		t.Fatalf("HTTPS listeners = %d, want 1 shared wildcard listener across namespaces", httpsListeners)
	}
}
