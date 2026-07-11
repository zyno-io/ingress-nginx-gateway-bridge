// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	"context"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestTranslateCommonAnnotations(t *testing.T) {
	ing := testIngress(map[string]string{
		annProxyBodySize:        "512m",
		annProxyReadTimeout:     "3600",
		annProxyBuffering:       "off",
		annEnableCORS:           "true",
		annCORSAllowOrigin:      "https://zyno.io, https://*.zyno.io",
		annCORSAllowCredentials: "false",
		annUpstreamVHost:        "backend.zyno.io",
	})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", plan.Issues)
	}
	if len(plan.HTTPRoutes) != 2 {
		t.Fatalf("HTTPRoutes = %d, want application + redirect", len(plan.HTTPRoutes))
	}
	if len(plan.ClientSettingsPolicies) != 1 || len(plan.ProxySettingsPolicies) != 1 {
		t.Fatalf("expected client and proxy policies, got %#v", plan)
	}
	application := plan.HTTPRoutes[0]
	if got := string(*application.Spec.ParentRefs[0].SectionName); got != "https" {
		t.Fatalf("parent section = %q", got)
	}
	if len(application.Spec.Rules[0].Filters) != 2 {
		t.Fatalf("filters = %d, want CORS + host modifier", len(application.Spec.Rules[0].Filters))
	}
	if application.Spec.Rules[0].Filters[0].Type != gatewayv1.HTTPRouteFilterCORS {
		t.Fatalf("first filter = %s, want CORS", application.Spec.Rules[0].Filters[0].Type)
	}
}

func TestTranslateBasicAuth(t *testing.T) {
	ing := testIngress(map[string]string{annAuthType: "basic", annAuthSecret: "users"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.AuthenticationFilters) != 1 {
		t.Fatalf("basic auth was not translated: %#v", plan)
	}
	if got := plan.AuthenticationFilters[0].Spec.Basic.SecretRef.Name; got != "users" {
		t.Fatalf("secret = %q", got)
	}
}

func TestTranslateExternalAuth(t *testing.T) {
	ing := testIngress(map[string]string{
		annAuthURL:             "https://auth.zyno.io/validate",
		annAuthResponseHeaders: "X-Zyno-User, X-Zyno-Tenant",
	})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.SnippetsFilters) != 1 {
		t.Fatalf("external auth was not translated: %#v", plan)
	}
	joined := ""
	for _, snippet := range plan.SnippetsFilters[0].Spec.Snippets {
		joined += snippet.Value
	}
	for _, expected := range []string{"auth_request", "proxy_ssl_server_name on", "proxy_set_header X-Zyno-User"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("generated external auth snippets do not contain %q:\n%s", expected, joined)
		}
	}
}

func TestTranslateAuthProxySetHeaders(t *testing.T) {
	ing := testIngress(map[string]string{
		annAuthURL:             "http://auth.apps.svc.cluster.local:8080/validate",
		annAuthProxySetHeaders: "auth-headers",
	})
	resolver := func(_ context.Context, namespace, name string) (map[string]string, error) {
		if namespace != "apps" || name != "auth-headers" {
			t.Fatalf("unexpected ConfigMap reference %s/%s", namespace, name)
		}
		return map[string]string{"Authorization": "$http_authorization"}, nil
	}
	plan := Translate(context.Background(), ing, testOptions(), nil, resolver)
	if plan.Fatal() || len(plan.SnippetsFilters) != 1 {
		t.Fatalf("auth proxy headers were not translated: %#v", plan)
	}
	if got := plan.SnippetsFilters[0].Spec.Snippets[0].Value; !strings.Contains(got, "proxy_set_header Authorization $http_authorization;") {
		t.Fatalf("generated auth location does not contain ConfigMap header:\n%s", got)
	}
}

func TestTranslateVerifiedHTTPSBackend(t *testing.T) {
	ing := testIngress(map[string]string{
		annBackendProtocol:    "HTTPS",
		annProxyHTTPVersion:   "1.1",
		annProxySSLVerify:     "on",
		annProxySSLServerName: "on",
		annProxySSLName:       "kubernetes.default.svc",
		annProxySSLSecret:     "apps/kubernetes-server-ca",
	})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.BackendTLSPolicies) != 1 {
		t.Fatalf("verified HTTPS backend was not translated: %#v", plan)
	}
	validation := plan.BackendTLSPolicies[0].Spec.Validation
	if validation.Hostname != "kubernetes.default.svc" || validation.CACertificateRefs[0].Name != "kubernetes-server-ca" {
		t.Fatalf("unexpected BackendTLSPolicy validation: %#v", validation)
	}
}

func TestTranslateRejectsUnverifiedHTTPSBackend(t *testing.T) {
	ing := testIngress(map[string]string{annBackendProtocol: "HTTPS"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if !plan.Fatal() {
		t.Fatal("unverified HTTPS backend was accepted")
	}
}

func TestTranslateRejectsUnknownAndRawSnippets(t *testing.T) {
	ing := testIngress(map[string]string{
		annotationPrefix + "mystery": "true",
		annServerSnippet:             "return 418;",
	})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if !plan.Fatal() {
		t.Fatal("strict translation accepted unknown and disabled raw snippets")
	}
}

func TestCaptureRewriteUsesGeneratedSnippet(t *testing.T) {
	ing := testIngress(map[string]string{annRewriteTarget: "/$2"})
	implementationSpecific := networkingv1.PathTypeImplementationSpecific
	ing.Spec.Rules[0].HTTP.Paths[0].Path = `/codesign(/|$)(.*)`
	ing.Spec.Rules[0].HTTP.Paths[0].PathType = &implementationSpecific
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.SnippetsFilters) != 1 {
		t.Fatalf("capture rewrite was not translated: %#v", plan)
	}
	match := plan.HTTPRoutes[0].Spec.Rules[0].Matches[0]
	if *match.Path.Type != gatewayv1.PathMatchRegularExpression {
		t.Fatalf("path type = %s, want RegularExpression", *match.Path.Type)
	}
}

func TestBuildManagedGatewayReportsTLSConflict(t *testing.T) {
	first := testIngress(nil)
	second := testIngress(nil)
	second.Name = "other"
	second.UID = "other-uid"
	second.Spec.TLS[0].SecretName = "other-cert"
	plan := BuildManagedGateway([]networkingv1.Ingress{*first, *second}, ManagedGatewayOptions{
		Namespace: "gateway", Name: "public", ClassName: "nginx", HTTPSectionName: "http", HTTPSSectionName: "https",
	})
	if len(plan.Issues[types.NamespacedName{Namespace: first.Namespace, Name: first.Name}]) == 0 {
		t.Fatal("expected a TLS conflict on the first Ingress")
	}
	if len(plan.Gateway.Spec.Listeners) != 2 {
		t.Fatalf("listeners = %d, want HTTP + one deterministic TLS listener", len(plan.Gateway.Spec.Listeners))
	}
}

func TestWildcardTLSSelectsWildcardListener(t *testing.T) {
	ing := testIngress(nil)
	ing.Spec.Rules[0].Host = "app.example.com"
	ing.Spec.TLS[0].Hosts = []string{"*.example.com"}
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", plan.Issues)
	}
	got := string(*plan.HTTPRoutes[0].Spec.ParentRefs[0].SectionName)
	if want := "https"; got != want {
		t.Fatalf("listener = %q, want %q", got, want)
	}
}

func TestSSLRedirectFalseAttachesHTTPAndHTTPS(t *testing.T) {
	ing := testIngress(map[string]string{annSSLRedirect: "false"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.HTTPRoutes) != 1 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if got := len(plan.HTTPRoutes[0].Spec.ParentRefs); got != 2 {
		t.Fatalf("parent refs = %d, want HTTP and HTTPS", got)
	}
}

func TestEmptyTLSHostsInferIngressRuleHosts(t *testing.T) {
	ing := testIngress(nil)
	ing.Spec.TLS[0].Hosts = nil
	plan := BuildManagedGateway([]networkingv1.Ingress{*ing}, ManagedGatewayOptions{
		Namespace: "gateway", Name: "public", ClassName: "nginx", HTTPSectionName: "http", HTTPSSectionName: "https",
	})
	if _, found := plan.TLSHosts["app.zyno.io"]; !found {
		t.Fatalf("inferred TLS host is missing: %#v", plan.TLSHosts)
	}
	options := testOptions()
	options.TLSHosts = plan.TLSHosts
	translated := Translate(context.Background(), ing, options, nil, nil)
	if translated.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", translated.Issues)
	}
	if got := string(*translated.HTTPRoutes[0].Spec.ParentRefs[0].SectionName); got != "https" {
		t.Fatalf("listener = %q, want https", got)
	}
}

func TestSharedHostTLSAttachesSiblingRoute(t *testing.T) {
	ing := testIngress(map[string]string{annSSLRedirect: "false"})
	ing.Spec.TLS = nil
	options := testOptions()
	options.TLSHosts = map[string]struct{}{"app.zyno.io": {}}
	plan := Translate(context.Background(), ing, options, nil, nil)
	if plan.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", plan.Issues)
	}
	if got := len(plan.HTTPRoutes[0].Spec.ParentRefs); got != 2 {
		t.Fatalf("parent refs = %d, want HTTP and inherited HTTPS", got)
	}
}

func TestRejectsIngressNginxEscapedRequestURI(t *testing.T) {
	ing := testIngress(map[string]string{
		annAuthURL:    "https://auth.zyno.dev/oauth2/auth",
		annAuthSignin: "https://auth.zyno.dev/oauth2/start?rd=$scheme://$http_host$escaped_request_uri",
	})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if !plan.Fatal() {
		t.Fatal("ingress-nginx-specific auth-signin variable was accepted")
	}
	if len(plan.SnippetsFilters) != 0 {
		t.Fatal("invalid auth-signin emitted a SnippetsFilter")
	}
}

func testIngress(annotations map[string]string) *networkingv1.Ingress {
	pathType := networkingv1.PathTypePrefix
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app", Namespace: "apps", UID: types.UID("app-uid"), Annotations: annotations,
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{Hosts: []string{"app.zyno.io"}, SecretName: "app-tls"}},
			Rules: []networkingv1.IngressRule{{
				Host: "app.zyno.io",
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

func testOptions() Options {
	return Options{
		Gateway: GatewayOptions{
			Namespace: "gateway", Name: "public", HTTPSectionName: "http", HTTPSSectionName: "https", ManagedListeners: true,
		},
		Strict: true,
	}
}
