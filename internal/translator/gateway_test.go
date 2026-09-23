// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	"context"
	"fmt"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func tlsIngress(namespace, name, secret string, hosts ...string) *networkingv1.Ingress {
	pathType := networkingv1.PathTypePrefix
	rules := make([]networkingv1.IngressRule, 0, len(hosts))
	for _, host := range hosts {
		rules = append(rules, networkingv1.IngressRule{
			Host: host,
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path: "/", PathType: &pathType,
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
						Name: "app", Port: networkingv1.ServiceBackendPort{Number: 8080},
					}},
				}},
			}},
		})
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID(namespace + "/" + name)},
		Spec: networkingv1.IngressSpec{
			TLS:   []networkingv1.IngressTLS{{Hosts: append([]string(nil), hosts...), SecretName: secret}},
			Rules: rules,
		},
	}
}

func managedOptions() ManagedGatewayOptions {
	return ManagedGatewayOptions{
		Namespace: "gateway", Name: "public", ClassName: "nginx",
		HTTPSectionName: "http", HTTPSSectionName: "https",
	}
}

func certInfo(fingerprint string, wildcardSANs ...string) CertificateInfo {
	return CertificateInfo{Fingerprint: fingerprint, WildcardSANs: wildcardSANs}
}

func secretKey(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}

func httpsListenerCount(gw gatewayv1.Gateway) int {
	count := 0
	for _, l := range gw.Spec.Listeners {
		if l.Protocol == gatewayv1.HTTPSProtocolType {
			count++
		}
	}
	return count
}

func TestWildcardCollapseSingleWildcard(t *testing.T) {
	ing := tlsIngress("apps", "app", "wild", "a.s24.dev", "b.s24.dev")
	options := managedOptions()
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("apps", "wild"): certInfo("fp-wild", "*.s24.dev"),
	}
	plan := BuildManagedGateway([]networkingv1.Ingress{*ing}, options)
	if len(plan.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", plan.Issues)
	}
	if got := httpsListenerCount(plan.Gateway); got != 1 {
		t.Fatalf("HTTPS listeners = %d, want 1 shared wildcard listener", got)
	}
	refA, refB := plan.TLSSections["a.s24.dev"], plan.TLSSections["b.s24.dev"]
	if refA != refB {
		t.Fatalf("a.s24.dev and b.s24.dev listener refs differ: %#v vs %#v", refA, refB)
	}
	if refA.Kind != GatewayKind {
		t.Fatalf("listener ref kind = %s, want Gateway", refA.Kind)
	}
	if _, ok := plan.TLSHosts["a.s24.dev"]; !ok {
		t.Fatal("a.s24.dev missing from TLSHosts")
	}
	if _, ok := plan.TLSHosts["b.s24.dev"]; !ok {
		t.Fatal("b.s24.dev missing from TLSHosts")
	}
	if _, ok := plan.TLSHosts["*.s24.dev"]; ok {
		t.Fatal("synthetic wildcard target must not appear in TLSHosts (declared-only)")
	}
}

func TestWildcardCollapseMultiLabelStaysExact(t *testing.T) {
	ing := tlsIngress("apps", "app", "wild", "a.s24.dev", "x.y.s24.dev")
	options := managedOptions()
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("apps", "wild"): certInfo("fp-wild", "*.s24.dev"),
	}
	plan := BuildManagedGateway([]networkingv1.Ingress{*ing}, options)
	if len(plan.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", plan.Issues)
	}
	if got := httpsListenerCount(plan.Gateway); got != 2 {
		t.Fatalf("HTTPS listeners = %d, want wildcard + exact multi-label listener", got)
	}
	if plan.TLSSections["x.y.s24.dev"] == plan.TLSSections["a.s24.dev"] {
		t.Fatal("x.y.s24.dev must not collapse into the single-label wildcard")
	}
}

func TestWildcardCollapseMixedWithNonCollapsible(t *testing.T) {
	wildIng := tlsIngress("apps", "wild-app", "wild", "a.s24.dev", "b.s24.dev")
	plainIng := tlsIngress("apps", "plain-app", "plain", "c.example.com")
	options := managedOptions()
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("apps", "wild"): certInfo("fp-wild", "*.s24.dev"),
		// "plain" has no entry: not collapsible.
	}
	plan := BuildManagedGateway([]networkingv1.Ingress{*wildIng, *plainIng}, options)
	if len(plan.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", plan.Issues)
	}
	if got := httpsListenerCount(plan.Gateway); got != 2 {
		t.Fatalf("HTTPS listeners = %d, want wildcard + exact", got)
	}
	if plan.TLSSections["a.s24.dev"] != plan.TLSSections["b.s24.dev"] {
		t.Fatal("a.s24.dev and b.s24.dev should share the wildcard listener")
	}
	if plan.TLSSections["c.example.com"] == plan.TLSSections["a.s24.dev"] {
		t.Fatal("c.example.com must not join the wildcard listener")
	}
}

func TestWildcardCollapseIdenticalCertificatesShareListener(t *testing.T) {
	alpha := tlsIngress("alpha", "app", "wild", "a.s24.dev")
	beta := tlsIngress("beta", "app", "wild", "b.s24.dev")
	options := managedOptions()
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("alpha", "wild"): certInfo("fp-shared", "*.s24.dev"),
		secretKey("beta", "wild"):  certInfo("fp-shared", "*.s24.dev"),
	}
	plan := BuildManagedGateway([]networkingv1.Ingress{*alpha, *beta}, options)
	if len(plan.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", plan.Issues)
	}
	if got := httpsListenerCount(plan.Gateway); got != 1 {
		t.Fatalf("HTTPS listeners = %d, want one shared listener for identical certs", got)
	}
	placement, ok := plan.Placements["*.s24.dev"]
	if !ok {
		t.Fatal("missing wildcard placement")
	}
	if placement.Secret != secretKey("alpha", "wild") {
		t.Fatalf("canonical secret = %s, want alpha/wild (lexicographically first)", placement.Secret)
	}
	if len(plan.ReferenceGrants) != 1 {
		t.Fatalf("grants = %d, want exactly one (for alpha/wild)", len(plan.ReferenceGrants))
	}
	if plan.ReferenceGrants[0].Namespace != "alpha" {
		t.Fatalf("grant namespace = %s, want alpha", plan.ReferenceGrants[0].Namespace)
	}
}

func TestWildcardCollapseDifferingCertificatesPicksLargerClass(t *testing.T) {
	alpha := tlsIngress("alpha", "app", "wild", "a.s24.dev")
	beta := tlsIngress("beta", "app", "wild", "b.s24.dev", "c.s24.dev")
	options := managedOptions()
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("alpha", "wild"): certInfo("fp-alpha", "*.s24.dev"),
		secretKey("beta", "wild"):  certInfo("fp-beta", "*.s24.dev"),
	}
	plan := BuildManagedGateway([]networkingv1.Ingress{*alpha, *beta}, options)
	if len(plan.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", plan.Issues)
	}
	placement, ok := plan.Placements["*.s24.dev"]
	if !ok || placement.Secret != secretKey("beta", "wild") {
		t.Fatalf("wildcard winner = %#v, want beta/wild (2 hosts beats 1)", placement)
	}
	if plan.TLSSections["a.s24.dev"] == plan.TLSSections["b.s24.dev"] {
		t.Fatal("alpha's host must fall back to its own exact listener")
	}
	if len(plan.ReferenceGrants) != 2 {
		t.Fatalf("grants = %d, want 2 (alpha exact + beta wildcard)", len(plan.ReferenceGrants))
	}
}

func TestWildcardCollapseChurnMinimization(t *testing.T) {
	options := managedOptions()
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("apps", "alpha-cert"): certInfo("fp-alpha", "*.s24.dev"),
		secretKey("apps", "beta-cert"):  certInfo("fp-beta", "*.s24.dev"),
	}

	t.Run("incumbent stays despite a larger challenger", func(t *testing.T) {
		alpha := tlsIngress("apps", "alpha-app", "alpha-cert", "a1.s24.dev", "a2.s24.dev")
		beta := tlsIngress("apps", "beta-app", "beta-cert", "b1.s24.dev", "b2.s24.dev", "b3.s24.dev")
		opts := options
		opts.CurrentPlacements = map[string]ListenerPlacement{
			"*.s24.dev":  {ListenerSet: 0, Secret: secretKey("apps", "alpha-cert")},
			"b1.s24.dev": {ListenerSet: 0, Secret: secretKey("apps", "beta-cert")},
			"b2.s24.dev": {ListenerSet: 0, Secret: secretKey("apps", "beta-cert")},
		}
		plan := BuildManagedGateway([]networkingv1.Ingress{*alpha, *beta}, opts)
		placement := plan.Placements["*.s24.dev"]
		if placement.Secret != secretKey("apps", "alpha-cert") {
			t.Fatalf("winner = %#v, want alpha-cert to stay (lower churn)", placement)
		}
	})

	t.Run("shrinking incumbent loses to the larger remaining class", func(t *testing.T) {
		alpha := tlsIngress("apps", "alpha-app", "alpha-cert", "a1.s24.dev")
		beta := tlsIngress("apps", "beta-app", "beta-cert", "b1.s24.dev", "b2.s24.dev")
		opts := options
		opts.CurrentPlacements = map[string]ListenerPlacement{
			"*.s24.dev": {ListenerSet: 0, Secret: secretKey("apps", "alpha-cert")},
		}
		plan := BuildManagedGateway([]networkingv1.Ingress{*alpha, *beta}, opts)
		placement := plan.Placements["*.s24.dev"]
		if placement.Secret != secretKey("apps", "beta-cert") {
			t.Fatalf("winner = %#v, want beta-cert to take over (larger, lower churn)", placement)
		}
	})
}

func TestWildcardCollapsePinnedLiteralWildcardWins(t *testing.T) {
	pinned := tlsIngress("apps", "pinned-app", "pinned-cert", "*.s24.dev")

	t.Run("different fingerprint stays exact", func(t *testing.T) {
		collapsing := tlsIngress("apps", "collapsing-app", "collapse-cert", "a.s24.dev")
		options := managedOptions()
		options.Certificates = map[types.NamespacedName]CertificateInfo{
			secretKey("apps", "pinned-cert"):   certInfo("fp-pinned", "*.s24.dev"),
			secretKey("apps", "collapse-cert"): certInfo("fp-collapse", "*.s24.dev"),
		}
		plan := BuildManagedGateway([]networkingv1.Ingress{*pinned, *collapsing}, options)
		placement := plan.Placements["*.s24.dev"]
		if placement.Secret != secretKey("apps", "pinned-cert") {
			t.Fatalf("pinned literal wildcard must always win: %#v", placement)
		}
		if plan.TLSSections["a.s24.dev"] == plan.TLSSections["*.s24.dev"] {
			t.Fatal("a.s24.dev must fall back to an exact listener when its cert differs from the pinned one")
		}
	})

	t.Run("same fingerprint joins the pinned listener", func(t *testing.T) {
		collapsing := tlsIngress("apps", "collapsing-app", "collapse-cert", "a.s24.dev")
		options := managedOptions()
		options.Certificates = map[types.NamespacedName]CertificateInfo{
			secretKey("apps", "pinned-cert"):   certInfo("fp-shared", "*.s24.dev"),
			secretKey("apps", "collapse-cert"): certInfo("fp-shared", "*.s24.dev"),
		}
		plan := BuildManagedGateway([]networkingv1.Ingress{*pinned, *collapsing}, options)
		if plan.TLSSections["a.s24.dev"] != plan.TLSSections["*.s24.dev"] {
			t.Fatal("a.s24.dev should join the pinned wildcard listener when certificates match")
		}
	})
}

func TestWildcardCollapseKeepsCurrentSecretAmongIdenticalCopies(t *testing.T) {
	alpha := tlsIngress("alpha", "app", "wild", "a.s24.dev")
	beta := tlsIngress("beta", "app", "wild", "b.s24.dev")
	options := managedOptions()
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("alpha", "wild"): certInfo("fp-shared", "*.s24.dev"),
		secretKey("beta", "wild"):  certInfo("fp-shared", "*.s24.dev"),
	}
	options.CurrentPlacements = map[string]ListenerPlacement{
		"*.s24.dev": {ListenerSet: 0, Secret: secretKey("beta", "wild")},
	}
	plan := BuildManagedGateway([]networkingv1.Ingress{*alpha, *beta}, options)
	placement := plan.Placements["*.s24.dev"]
	if placement.Secret != secretKey("beta", "wild") {
		t.Fatalf("canonical secret = %s, want beta/wild to stay canonical", placement.Secret)
	}
}

func TestWildcardCollapseDisabledWhenCertificatesNil(t *testing.T) {
	ing := tlsIngress("apps", "app", "wild", "a.s24.dev", "b.s24.dev")
	options := managedOptions()
	// options.Certificates left nil: collapse must be fully disabled.
	plan := BuildManagedGateway([]networkingv1.Ingress{*ing}, options)
	if got := httpsListenerCount(plan.Gateway); got != 2 {
		t.Fatalf("HTTPS listeners = %d, want 2 exact listeners with collapse disabled", got)
	}
}

func TestWildcardCollapseSameHostConflictStillFatal(t *testing.T) {
	first := tlsIngress("apps", "first", "wild-a", "a.s24.dev")
	second := tlsIngress("apps", "second", "wild-b", "a.s24.dev")
	options := managedOptions()
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("apps", "wild-a"): certInfo("fp-a", "*.s24.dev"),
		secretKey("apps", "wild-b"): certInfo("fp-b", "*.s24.dev"),
	}
	plan := BuildManagedGateway([]networkingv1.Ingress{*first, *second}, options)
	if len(plan.Issues[types.NamespacedName{Namespace: "apps", Name: "first"}]) == 0 {
		t.Fatal("expected a TLS conflict issue on the first Ingress")
	}
	if len(plan.Issues[types.NamespacedName{Namespace: "apps", Name: "second"}]) == 0 {
		t.Fatal("expected a TLS conflict issue on the second Ingress")
	}
}

func TestTranslateAttachesCollapsedListenerSection(t *testing.T) {
	ing := tlsIngress("apps", "app", "wild", "a.s24.dev")
	ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{
		Host: "c.s24.dev",
		IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
			Paths: ing.Spec.Rules[0].HTTP.Paths,
		}},
	})
	gwOptions := managedOptions()
	gwOptions.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("apps", "wild"): certInfo("fp-wild", "*.s24.dev"),
	}
	plan := BuildManagedGateway([]networkingv1.Ingress{*ing}, gwOptions)
	if len(plan.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", plan.Issues)
	}

	options := Options{Gateway: GatewayOptions{
		Namespace: "gateway", Name: "public", HTTPSectionName: "http", HTTPSSectionName: "https",
		TLSSections: plan.TLSSections,
	}, TLSHosts: plan.TLSHosts, Strict: true}
	translated := Translate(context.Background(), ing, options, nil, nil)
	if translated.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", translated.Issues)
	}
	var aRoute, cRoute *gatewayv1.HTTPRoute
	for idx := range translated.HTTPRoutes {
		route := &translated.HTTPRoutes[idx]
		if len(route.Spec.Hostnames) == 0 || isRedirectRoute(route) {
			continue
		}
		switch route.Spec.Hostnames[0] {
		case "a.s24.dev":
			aRoute = route
		case "c.s24.dev":
			cRoute = route
		}
	}
	if aRoute == nil || cRoute == nil {
		t.Fatalf("expected routes for both hosts: %#v", translated.HTTPRoutes)
	}
	wantSection := plan.TLSSections["a.s24.dev"].SectionName
	if got := string(*aRoute.Spec.ParentRefs[0].SectionName); got != wantSection {
		t.Fatalf("a.s24.dev parent section = %q, want collapsed section %q", got, wantSection)
	}
	if got := len(cRoute.Spec.ParentRefs); got != 1 {
		t.Fatalf("c.s24.dev parent refs = %d, want HTTP only (undeclared TLS host)", got)
	}
	if got := string(*cRoute.Spec.ParentRefs[0].SectionName); got != "http" {
		t.Fatalf("c.s24.dev parent section = %q, want http", got)
	}
}

func isRedirectRoute(route *gatewayv1.HTTPRoute) bool {
	for _, rule := range route.Spec.Rules {
		for _, filter := range rule.Filters {
			if filter.Type == gatewayv1.HTTPRouteFilterRequestRedirect {
				return true
			}
		}
	}
	return false
}

func manyHostIngresses(namespace string, count int, secretPrefix, hostSuffix string) []networkingv1.Ingress {
	ingresses := make([]networkingv1.Ingress, 0, count)
	for i := 1; i <= count; i++ {
		host := fmt.Sprintf("h%03d.%s", i, hostSuffix)
		secret := fmt.Sprintf("%s-%03d", secretPrefix, i)
		ingresses = append(ingresses, *tlsIngress(namespace, fmt.Sprintf("app-%03d", i), secret, host))
	}
	return ingresses
}

func TestOverflowSpreadsAcrossListenerSets(t *testing.T) {
	ingresses := manyHostIngresses("apps", 130, "cert", "s24.dev")
	options := managedOptions()
	options.ListenerSetOverflow = true
	plan := BuildManagedGateway(ingresses, options)
	if len(plan.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", plan.Issues)
	}
	if got := len(plan.Gateway.Spec.Listeners); got != 64 {
		t.Fatalf("Gateway listeners = %d, want 64 (1 HTTP + 63 HTTPS)", got)
	}
	if got := len(plan.ListenerSets); got != 2 {
		t.Fatalf("ListenerSets = %d, want 2", got)
	}
	if got := len(plan.ListenerSets[0].Spec.Listeners); got != 64 {
		t.Fatalf("set 1 listeners = %d, want 64", got)
	}
	if got := len(plan.ListenerSets[1].Spec.Listeners); got != 3 {
		t.Fatalf("set 2 listeners = %d, want 3 (130 - 63 - 64)", got)
	}
	set1 := plan.ListenerSets[0]
	if want := ManagedListenerSetName("public", 1); set1.Name != want {
		t.Fatalf("set 1 name = %s, want %s", set1.Name, want)
	}
	if set1.Labels[ManagedByLabel] != ControllerName || set1.Labels[GatewayLabel] != GatewayLabelValue("gateway", "public") ||
		set1.Labels[ListenerSetIndexLabel] != "1" {
		t.Fatalf("set 1 labels incomplete: %#v", set1.Labels)
	}
	if set1.Spec.ParentRef.Name != "public" || set1.Spec.ParentRef.Kind == nil || string(*set1.Spec.ParentRef.Kind) != GatewayKind {
		t.Fatalf("set 1 parentRef incorrect: %#v", set1.Spec.ParentRef)
	}
	if plan.Gateway.Spec.AllowedListeners == nil || plan.Gateway.Spec.AllowedListeners.Namespaces == nil ||
		*plan.Gateway.Spec.AllowedListeners.Namespaces.From != gatewayv1.NamespacesFromSame {
		t.Fatal("Gateway must allow same-namespace ListenerSets once any are emitted")
	}
	// h001-h063 land on the Gateway, h064-h127 fill set 1, h128-h130 spill into set 2.
	ref, ok := plan.TLSSections["h128.s24.dev"]
	if !ok || ref.Kind != ListenerSetKind || ref.Name != ManagedListenerSetName("public", 2) {
		t.Fatalf("h128.s24.dev ref = %#v, want set 2", ref)
	}
}

func TestOverflowStickyPlacementAcrossReplans(t *testing.T) {
	ingresses := manyHostIngresses("apps", 70, "cert", "s24.dev")
	options := managedOptions()
	options.ListenerSetOverflow = true
	first := BuildManagedGateway(ingresses, options)
	if len(first.ListenerSets) != 1 {
		t.Fatalf("expected one overflow set, got %d", len(first.ListenerSets))
	}

	addition := tlsIngress("apps", "app-new", "cert-new", "a-new.s24.dev")
	options.CurrentPlacements = first.Placements
	second := BuildManagedGateway(append(append([]networkingv1.Ingress{}, ingresses...), *addition), options)

	for hostname, placement := range first.Placements {
		if got := second.Placements[hostname]; got != placement {
			t.Fatalf("placement for %s changed: had %#v, now %#v", hostname, placement, got)
		}
	}
	newPlacement, ok := second.Placements["a-new.s24.dev"]
	if !ok {
		t.Fatal("a-new.s24.dev was not placed")
	}
	if newPlacement.ListenerSet == 0 {
		t.Fatalf("a-new.s24.dev landed on the Gateway despite it being full: %#v", newPlacement)
	}
}

func TestOverflowShrinkPrunesEmptySets(t *testing.T) {
	ingresses := manyHostIngresses("apps", 70, "cert", "s24.dev")
	options := managedOptions()
	options.ListenerSetOverflow = true
	first := BuildManagedGateway(ingresses, options)
	if len(first.ListenerSets) != 1 {
		t.Fatalf("expected one overflow set, got %d", len(first.ListenerSets))
	}

	// Remove exactly the hosts that landed in the overflow set.
	overflowHosts := make(map[string]struct{})
	for hostname, placement := range first.Placements {
		if placement.ListenerSet > 0 {
			overflowHosts[hostname] = struct{}{}
		}
	}
	remaining := make([]networkingv1.Ingress, 0, len(ingresses))
	for _, ing := range ingresses {
		if _, dropped := overflowHosts[ing.Spec.TLS[0].Hosts[0]]; dropped {
			continue
		}
		remaining = append(remaining, ing)
	}
	options.CurrentPlacements = first.Placements
	shrunk := BuildManagedGateway(remaining, options)
	if len(shrunk.ListenerSets) != 0 {
		t.Fatalf("ListenerSets = %d, want 0 after removing all overflow hosts", len(shrunk.ListenerSets))
	}
	if shrunk.Gateway.Spec.AllowedListeners != nil {
		t.Fatal("AllowedListeners must be cleared once no ListenerSets remain and AllowListenerSets is false")
	}

	// Removing hosts that live on the Gateway must not pull overflow hosts back.
	fewerGatewayHosts := remaining[:len(remaining)-5]
	options.CurrentPlacements = first.Placements
	full := append(append([]networkingv1.Ingress{}, fewerGatewayHosts...), overflowIngresses(ingresses, overflowHosts)...)
	replanned := BuildManagedGateway(full, options)
	for hostname := range overflowHosts {
		if got := replanned.Placements[hostname]; got.ListenerSet == 0 {
			t.Fatalf("%s was pulled back onto the Gateway after it freed up capacity", hostname)
		}
	}
}

func overflowIngresses(all []networkingv1.Ingress, hosts map[string]struct{}) []networkingv1.Ingress {
	result := make([]networkingv1.Ingress, 0, len(hosts))
	for _, ing := range all {
		if _, ok := hosts[ing.Spec.TLS[0].Hosts[0]]; ok {
			result = append(result, ing)
		}
	}
	return result
}

func TestOverflowDisabledRejectsOnlyExcessHost(t *testing.T) {
	ingresses := manyHostIngresses("apps", 64, "cert", "s24.dev")
	options := managedOptions()
	options.ListenerSetOverflow = false
	plan := BuildManagedGateway(ingresses, options)

	// Hosts sort as h001..h064; the 64th (h064) cannot fit alongside 63 others.
	rejected := types.NamespacedName{Namespace: "apps", Name: "app-064"}
	if len(plan.Issues[rejected]) == 0 {
		t.Fatal("expected the 64th host's Ingress to carry an overflow error")
	}
	for i := 1; i < 64; i++ {
		name := types.NamespacedName{Namespace: "apps", Name: fmt.Sprintf("app-%03d", i)}
		if len(plan.Issues[name]) != 0 {
			t.Fatalf("Ingress %s unexpectedly has issues: %#v", name, plan.Issues[name])
		}
	}
	if _, ok := plan.TLSSections["h064.s24.dev"]; ok {
		t.Fatal("rejected host must not have a TLS section")
	}
	if _, ok := plan.TLSHosts["h064.s24.dev"]; !ok {
		t.Fatal("rejected host must remain a declared TLS host")
	}
}

func TestOverflowInheritsPlacementAcrossCollapse(t *testing.T) {
	options := managedOptions()
	options.ListenerSetOverflow = true
	options.Certificates = map[types.NamespacedName]CertificateInfo{
		secretKey("apps", "wild"): certInfo("fp-wild", "*.s24.dev"),
	}
	options.CurrentPlacements = map[string]ListenerPlacement{
		"a.s24.dev": {ListenerSet: 1, Secret: secretKey("apps", "wild")},
	}
	ing := tlsIngress("apps", "app", "wild", "a.s24.dev")
	plan := BuildManagedGateway([]networkingv1.Ingress{*ing}, options)
	placement, ok := plan.Placements["*.s24.dev"]
	if !ok {
		t.Fatal("wildcard listener was not placed")
	}
	if placement.ListenerSet != 1 {
		t.Fatalf("wildcard listener landed in set %d, want set 1 (inherited from a.s24.dev)", placement.ListenerSet)
	}
}

func TestTranslateListenerSetParentRef(t *testing.T) {
	ing := tlsIngress("apps", "app", "wild", "a.example.com")
	ref := ListenerRef{Kind: ListenerSetKind, Name: "public-1", SectionName: "https-a-example-com"}
	options := Options{Gateway: GatewayOptions{
		Namespace: "gateway", Name: "public", HTTPSectionName: "http", HTTPSSectionName: "https",
		TLSSections: map[string]ListenerRef{"a.example.com": ref},
	}, TLSHosts: map[string]struct{}{"a.example.com": {}}, Strict: true}

	plan := Translate(context.Background(), ing, options, nil, nil)
	if plan.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", plan.Issues)
	}
	var application *gatewayv1.HTTPRoute
	for idx := range plan.HTTPRoutes {
		if len(plan.HTTPRoutes[idx].Spec.ParentRefs) >= 1 && plan.HTTPRoutes[idx].Spec.ParentRefs[0].Kind != nil {
			application = &plan.HTTPRoutes[idx]
		}
	}
	if application == nil {
		t.Fatalf("no route carried a ListenerSet parentRef: %#v", plan.HTTPRoutes)
	}
	httpsRef := application.Spec.ParentRefs[0]
	if httpsRef.Group == nil || string(*httpsRef.Group) != gatewayv1.GroupName {
		t.Fatalf("HTTPS ref Group = %v, want %s", httpsRef.Group, gatewayv1.GroupName)
	}
	if httpsRef.Kind == nil || string(*httpsRef.Kind) != ListenerSetKind {
		t.Fatalf("HTTPS ref Kind = %v, want ListenerSet", httpsRef.Kind)
	}
	if httpsRef.Namespace == nil || string(*httpsRef.Namespace) != "gateway" {
		t.Fatalf("HTTPS ref Namespace = %v, want gateway", httpsRef.Namespace)
	}
	if httpsRef.SectionName == nil || string(*httpsRef.SectionName) != ref.SectionName {
		t.Fatalf("HTTPS ref SectionName = %v, want %s", httpsRef.SectionName, ref.SectionName)
	}

	for idx := range plan.HTTPRoutes {
		route := &plan.HTTPRoutes[idx]
		for _, parentRef := range route.Spec.ParentRefs {
			if parentRef.Kind != nil && string(*parentRef.Kind) == ListenerSetKind {
				continue
			}
			// Every non-ListenerSet ref (HTTP attach or the redirect route) stays byte-identical: no Group/Kind.
			if parentRef.Group != nil || parentRef.Kind != nil {
				t.Fatalf("Gateway parentRef unexpectedly carries Group/Kind: %#v", parentRef)
			}
		}
	}
}

func TestGrantsIncludeListenerSetOnlyWhenOverflowAvailable(t *testing.T) {
	ing := tlsIngress("apps", "app", "wild", "a.example.com")
	base := managedOptions()

	withOverflow := base
	withOverflow.ListenerSetOverflow = true
	planWith := BuildManagedGateway([]networkingv1.Ingress{*ing}, withOverflow)
	if len(planWith.ReferenceGrants) != 1 {
		t.Fatalf("expected exactly one grant, got %d", len(planWith.ReferenceGrants))
	}
	if got := len(planWith.ReferenceGrants[0].Spec.From); got != 2 {
		t.Fatalf("grant From entries = %d, want Gateway + ListenerSet", got)
	}

	withoutOverflow := base
	withoutOverflow.ListenerSetOverflow = false
	planWithout := BuildManagedGateway([]networkingv1.Ingress{*ing}, withoutOverflow)
	if got := len(planWithout.ReferenceGrants[0].Spec.From); got != 1 {
		t.Fatalf("grant From entries = %d, want Gateway only", got)
	}
}

func TestChangedTLSHosts(t *testing.T) {
	options := managedOptions()
	options.ListenerSetOverflow = true
	ing := tlsIngress("apps", "app", "wild", "a.s24.dev", "b.s24.dev")
	first := BuildManagedGateway([]networkingv1.Ingress{*ing}, options)
	if len(first.Issues) != 0 {
		t.Fatalf("unexpected issues: %#v", first.Issues)
	}

	// No changes: rebuilding from the same placements changes nothing.
	options.CurrentPlacements = first.Placements
	second := BuildManagedGateway([]networkingv1.Ingress{*ing}, options)
	if changed := ChangedTLSHosts(first.Placements, second, options); len(changed) != 0 {
		t.Fatalf("expected no changed hosts, got %#v", changed)
	}

	// A brand-new host with no previous placement counts as changed.
	third := tlsIngress("apps", "app2", "wild2", "c.s24.dev")
	combined := BuildManagedGateway([]networkingv1.Ingress{*ing, *third}, options)
	changed := ChangedTLSHosts(first.Placements, combined, options)
	if _, ok := changed["c.s24.dev"]; !ok {
		t.Fatalf("expected c.s24.dev to be reported changed: %#v", changed)
	}
	if _, ok := changed["a.s24.dev"]; ok {
		t.Fatalf("a.s24.dev should not have changed: %#v", changed)
	}
}

func TestRouteTLSHostnames(t *testing.T) {
	tlsHosts := map[string]struct{}{"a.example.com": {}, "*.wild.example.com": {}}
	ing := tlsIngress("apps", "app", "wild", "a.example.com", "untls.example.com")
	ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{Host: "sub.wild.example.com"})
	ing.Annotations = map[string]string{annServerAlias: "a.example.com, sub.wild.example.com, other.example.com"}

	got := RouteTLSHostnames(ing, tlsHosts)
	want := map[string]struct{}{"a.example.com": {}, "*.wild.example.com": {}}
	if len(got) != len(want) {
		t.Fatalf("RouteTLSHostnames = %#v, want %#v", got, want)
	}
	for _, host := range got {
		if _, ok := want[host]; !ok {
			t.Fatalf("unexpected hostname %q in %#v", host, got)
		}
	}
}
