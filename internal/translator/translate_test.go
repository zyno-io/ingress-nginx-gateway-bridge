// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
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
	if len(plan.SnippetsFilters) != 1 {
		t.Fatalf("CORS compatibility SnippetsFilter count = %d, want 1", len(plan.SnippetsFilters))
	}
	application := plan.HTTPRoutes[0]
	if got := string(*application.Spec.ParentRefs[0].SectionName); got != "https" {
		t.Fatalf("parent section = %q", got)
	}
	if len(application.Spec.Rules[0].Filters) != 3 {
		t.Fatalf("filters = %d, want CORS + URLRewrite + SnippetsFilter", len(application.Spec.Rules[0].Filters))
	}
	if application.Spec.Rules[0].Filters[0].Type != gatewayv1.HTTPRouteFilterCORS {
		t.Fatalf("first filter = %s, want CORS", application.Spec.Rules[0].Filters[0].Type)
	}
	hostFilter := application.Spec.Rules[0].Filters[1]
	if hostFilter.Type != gatewayv1.HTTPRouteFilterURLRewrite ||
		hostFilter.URLRewrite == nil ||
		hostFilter.URLRewrite.Hostname == nil ||
		*hostFilter.URLRewrite.Hostname != "backend.zyno.io" {
		t.Fatalf("second filter does not replace the upstream Host header: %#v", hostFilter)
	}
	if application.Spec.Rules[0].Filters[2].ExtensionRef == nil || application.Spec.Rules[0].Filters[2].ExtensionRef.Kind != "SnippetsFilter" {
		t.Fatalf("third filter does not reference the CORS compatibility SnippetsFilter: %#v", application.Spec.Rules[0].Filters[2])
	}
}

func TestTranslateUpstreamVHostUsesURLRewrite(t *testing.T) {
	ing := testIngress(map[string]string{annUpstreamVHost: "kubernetes.default.svc"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", plan.Issues)
	}
	if len(plan.SnippetsFilters) != 0 {
		t.Fatalf("upstream-vhost generated SnippetsFilters: %#v", plan.SnippetsFilters)
	}

	rule := plan.HTTPRoutes[0].Spec.Rules[0]
	if len(rule.Filters) != 1 {
		t.Fatalf("filters = %d, want one URLRewrite: %#v", len(rule.Filters), rule.Filters)
	}
	filter := rule.Filters[0]
	if filter.Type != gatewayv1.HTTPRouteFilterURLRewrite || filter.URLRewrite == nil || filter.URLRewrite.Hostname == nil {
		t.Fatalf("upstream-vhost filter = %#v, want URLRewrite", filter)
	}
	if got := *filter.URLRewrite.Hostname; got != "kubernetes.default.svc" {
		t.Fatalf("upstream-vhost hostname = %q, want kubernetes.default.svc", got)
	}
}

func TestTranslateUpstreamVHostMergesWithPathRewrite(t *testing.T) {
	ing := testIngress(map[string]string{
		annUpstreamVHost: "backend.zyno.io",
		annRewriteTarget: "/rewritten",
	})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", plan.Issues)
	}

	rule := plan.HTTPRoutes[0].Spec.Rules[0]
	if len(rule.Filters) != 1 {
		t.Fatalf("filters = %d, want one merged URLRewrite: %#v", len(rule.Filters), rule.Filters)
	}
	rewrite := rule.Filters[0].URLRewrite
	if rewrite == nil || rewrite.Hostname == nil || *rewrite.Hostname != "backend.zyno.io" {
		t.Fatalf("merged URLRewrite hostname = %#v", rewrite)
	}
	if rewrite.Path == nil || rewrite.Path.ReplaceFullPath == nil || *rewrite.Path.ReplaceFullPath != "/rewritten" {
		t.Fatalf("merged URLRewrite path = %#v", rewrite)
	}
}

func TestTranslateRejectsUnsafeUpstreamVHost(t *testing.T) {
	ing := testIngress(map[string]string{annUpstreamVHost: "first.example second.example"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if !plan.Fatal() {
		t.Fatalf("unsafe upstream-vhost was accepted: %#v", plan)
	}
	if len(plan.HTTPRoutes[0].Spec.Rules[0].Filters) != 0 {
		t.Fatalf("unsafe upstream-vhost generated filters: %#v", plan.HTTPRoutes[0].Spec.Rules[0].Filters)
	}
}

func TestCORSHidesUpstreamResponseHeaders(t *testing.T) {
	ing := testIngress(map[string]string{annEnableCORS: "true"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.SnippetsFilters) != 1 {
		t.Fatalf("CORS upstream response headers were not suppressed: %#v", plan)
	}
	got := plan.SnippetsFilters[0].Spec.Snippets[0].Value
	for _, header := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Expose-Headers",
		"Access-Control-Max-Age",
	} {
		if !strings.Contains(got, "proxy_hide_header "+header+";") {
			t.Fatalf("CORS compatibility snippet does not hide %s:\n%s", header, got)
		}
	}
	application := plan.HTTPRoutes[0]
	if len(application.Spec.Rules[0].Filters) != 2 || application.Spec.Rules[0].Filters[0].Type != gatewayv1.HTTPRouteFilterCORS {
		t.Fatalf("CORS and compatibility filters were not both attached: %#v", application.Spec.Rules[0].Filters)
	}
}

func TestProxyBufferSizePreservesIngressNginxBufferRelationship(t *testing.T) {
	ing := testIngress(map[string]string{annProxyBufferSize: "16k"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.ProxySettingsPolicies) != 1 {
		t.Fatalf("proxy-buffer-size was not translated: %#v", plan)
	}
	buffering := plan.ProxySettingsPolicies[0].Spec.Buffering
	if buffering == nil || buffering.BufferSize == nil || *buffering.BufferSize != "16k" {
		t.Fatalf("buffer size = %#v, want 16k", buffering)
	}
	if buffering.Buffers == nil || buffering.Buffers.Number != 4 || buffering.Buffers.Size != "16k" {
		t.Fatalf("proxy buffers = %#v, want ingress-nginx default 4 16k", buffering.Buffers)
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
		annAuthMethod:          "POST",
		annAuthRequestRedirect: "$scheme://$http_host$request_uri",
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
	for _, expected := range []string{
		"auth_request",
		"proxy_pass_request_headers on",
		"proxy_pass_request_body off",
		"proxy_set_header Content-Length \"\"",
		"proxy_set_header Proxy \"\"",
		"proxy_method POST",
		"proxy_set_header Host $http_host",
		"proxy_set_header X-Original-URL $scheme://$http_host$request_uri",
		"proxy_set_header X-Original-Method $request_method",
		"proxy_set_header X-Sent-From \"nginx-ingress-controller\"",
		"proxy_set_header X-Real-IP $remote_addr",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for",
		"proxy_set_header X-Forwarded-Host $http_host",
		"proxy_set_header X-Forwarded-Port $server_port",
		"proxy_set_header X-Forwarded-Proto $scheme",
		"proxy_set_header X-Forwarded-Scheme $scheme",
		"proxy_set_header X-Scheme $scheme",
		"proxy_set_header X-Auth-Request-Redirect $scheme://$http_host$request_uri",
		"proxy_ssl_server_name on",
		"proxy_set_header X-Zyno-User",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("generated external auth snippets do not contain %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "proxy_set_header Content-Type \"\"") {
		t.Fatalf("generated external auth snippets clear Content-Type instead of forwarding it:\n%s", joined)
	}
}

func TestTranslateConsolidatesCanaryAndProtectsExternalAuthBodySize(t *testing.T) {
	primary := testIngress(map[string]string{
		annProxyBodySize: "8m",
		annAuthURL:       "http://auth.apps.svc.cluster.local:8080/authz",
	})
	canary := testIngress(map[string]string{
		annCanary:              "true",
		annCanaryByHeader:      "x-zyno-debug",
		annCanaryByHeaderValue: "true",
		// ingress-nginx ignores this and inherits the primary setting.
		annProxyBodySize: "1m",
	})
	canary.Name = "app-debug"
	canary.UID = types.UID("app-debug-uid")
	canary.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name = "app-debug"

	options := testOptions()
	options.CanaryIngresses = []networkingv1.Ingress{*canary}
	plan := Translate(context.Background(), primary, options, nil, nil)
	if plan.Fatal() {
		t.Fatalf("consolidated canary plan unexpectedly fatal: %#v", plan.Issues)
	}
	if len(plan.HTTPRoutes) != 2 {
		t.Fatalf("HTTPRoutes = %d, want one application route and one redirect", len(plan.HTTPRoutes))
	}
	route := plan.HTTPRoutes[0]
	if len(route.Spec.Rules) != 2 {
		t.Fatalf("application route rules = %d, want primary and canary", len(route.Spec.Rules))
	}
	if got := route.Spec.Rules[0].BackendRefs[0].Name; got != "app" {
		t.Fatalf("primary backend = %q, want app", got)
	}
	canaryRule := route.Spec.Rules[1]
	if got := canaryRule.BackendRefs[0].Name; got != "app-debug" {
		t.Fatalf("canary backend = %q, want app-debug", got)
	}
	if len(canaryRule.Matches) != 1 || len(canaryRule.Matches[0].Headers) != 1 {
		t.Fatalf("canary rule does not contain one header match: %#v", canaryRule.Matches)
	}
	header := canaryRule.Matches[0].Headers[0]
	if header.Name != "x-zyno-debug" || header.Value != "true" {
		t.Fatalf("canary header match = %#v", header)
	}
	if len(plan.ClientSettingsPolicies) != 1 || plan.ClientSettingsPolicies[0].Spec.Body == nil ||
		plan.ClientSettingsPolicies[0].Spec.Body.MaxSize == nil || *plan.ClientSettingsPolicies[0].Spec.Body.MaxSize != "8m" {
		t.Fatalf("primary body policy was not inherited by the combined route: %#v", plan.ClientSettingsPolicies)
	}
	if len(plan.SnippetsFilters) != 1 {
		t.Fatalf("external auth SnippetsFilter count = %d, want 1", len(plan.SnippetsFilters))
	}
	serverSnippet := ""
	for _, snippet := range plan.SnippetsFilters[0].Spec.Snippets {
		if snippet.Context == "http.server" {
			serverSnippet = snippet.Value
		}
	}
	if !strings.Contains(serverSnippet, "location = /_ngib_auth_") || !strings.Contains(serverSnippet, "  client_max_body_size 8m;") {
		t.Fatalf("external auth location does not carry the primary body limit:\n%s", serverSnippet)
	}
}

func TestTranslateConsolidatesMultiPathPublicCanary(t *testing.T) {
	primary := testIngress(map[string]string{annProxyBodySize: "4m"})
	pathType := networkingv1.PathTypePrefix
	paths := []networkingv1.HTTPIngressPath{
		{
			Path: "/public", PathType: &pathType,
			Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
				Name: "app", Port: networkingv1.ServiceBackendPort{Number: 8080},
			}},
		},
		{
			Path: "/embedded", PathType: &pathType,
			Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
				Name: "app", Port: networkingv1.ServiceBackendPort{Number: 8080},
			}},
		},
		{
			Path: "/healthz", PathType: &pathType,
			Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
				Name: "app", Port: networkingv1.ServiceBackendPort{Number: 8080},
			}},
		},
	}
	primary.Spec.Rules[0].HTTP.Paths = paths
	canary := primary.DeepCopy()
	canary.Name = "app-public-debug"
	canary.Annotations = map[string]string{
		annCanary: "true", annCanaryByHeader: "x-zyno-debug", annCanaryByHeaderValue: "true",
	}
	for idx := range canary.Spec.Rules[0].HTTP.Paths {
		canary.Spec.Rules[0].HTTP.Paths[idx].Backend.Service.Name = "app-debug"
	}
	options := testOptions()
	options.CanaryIngresses = []networkingv1.Ingress{*canary}
	plan := Translate(context.Background(), primary, options, nil, nil)
	if plan.Fatal() {
		t.Fatalf("multi-path canary plan unexpectedly fatal: %#v", plan.Issues)
	}
	route := plan.HTTPRoutes[0]
	if len(route.Spec.Rules) != 6 {
		t.Fatalf("combined route rules = %d, want three primary and three canary rules", len(route.Spec.Rules))
	}
	for idx := 3; idx < 6; idx++ {
		rule := route.Spec.Rules[idx]
		if rule.BackendRefs[0].Name != "app-debug" || len(rule.Matches[0].Headers) != 1 {
			t.Fatalf("rule %d is not a debug header canary: %#v", idx, rule)
		}
	}
	if len(plan.ClientSettingsPolicies) != 1 || *plan.ClientSettingsPolicies[0].Spec.Body.MaxSize != "4m" {
		t.Fatalf("combined route does not have the primary 4m body policy: %#v", plan.ClientSettingsPolicies)
	}
}

func TestOverlappingNonCanaryBodySizeFailsInsteadOfEmittingIneffectiveSnippet(t *testing.T) {
	ing := testIngress(map[string]string{annProxyBodySize: "8m"})
	options := testOptions()
	options.SettingsAsSnippets = true
	plan := Translate(context.Background(), ing, options, nil, nil)
	if !plan.Fatal() {
		t.Fatalf("overlapping non-canary body size was accepted: %#v", plan)
	}
	if len(plan.ClientSettingsPolicies) != 0 {
		t.Fatalf("unexpected ClientSettingsPolicy: %#v", plan.ClientSettingsPolicies)
	}
	for _, filter := range plan.SnippetsFilters {
		for _, snippet := range filter.Spec.Snippets {
			if strings.Contains(snippet.Value, "client_max_body_size") {
				t.Fatalf("ineffective body-size snippet was emitted:\n%s", snippet.Value)
			}
		}
	}
}

func TestValidateCanaryRejectsUnsupportedAndInvalidHeaderModes(t *testing.T) {
	for _, test := range []struct {
		name        string
		annotations map[string]string
	}{
		{
			name: "missing header value",
			annotations: map[string]string{
				annCanary: "true", annCanaryByHeader: "x-zyno-debug",
			},
		},
		{
			name: "invalid header",
			annotations: map[string]string{
				annCanary: "true", annCanaryByHeader: "bad header", annCanaryByHeaderValue: "true",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ing := testIngress(test.annotations)
			issues := ValidateCanary(ing)
			if len(issues) != 1 || !issues[0].Fatal() {
				t.Fatalf("ValidateCanary() = %#v, want one fatal issue", issues)
			}
		})
	}
}

func TestValidateCanaryRejectsCatchAllBackend(t *testing.T) {
	ing := testIngress(map[string]string{
		annCanary: "true", annCanaryByHeader: "x-zyno-debug", annCanaryByHeaderValue: "true",
	})
	ing.Spec.DefaultBackend = ing.Spec.Rules[0].HTTP.Paths[0].Backend.DeepCopy()
	issues := ValidateCanary(ing)
	if len(issues) != 1 || !issues[0].Fatal() || issues[0].Field != "spec.defaultBackend" {
		t.Fatalf("ValidateCanary() = %#v, want one fatal default-backend issue", issues)
	}
}

func TestTranslateRejectsMultipleCanariesForOneRule(t *testing.T) {
	primary := testIngress(nil)
	first := testIngress(map[string]string{
		annCanary: "true", annCanaryByHeader: "x-zyno-debug", annCanaryByHeaderValue: "first",
	})
	first.Name = "first-canary"
	second := testIngress(map[string]string{
		annCanary: "true", annCanaryByHeader: "x-zyno-debug", annCanaryByHeaderValue: "second",
	})
	second.Name = "second-canary"
	options := testOptions()
	options.CanaryIngresses = []networkingv1.Ingress{*first, *second}
	plan := Translate(context.Background(), primary, options, nil, nil)
	if !plan.Fatal() {
		t.Fatalf("multiple canaries for one rule were accepted: %#v", plan)
	}
}

func TestTranslateRejectsResourceBackendWithoutPanicking(t *testing.T) {
	ing := testIngress(nil)
	ing.Spec.Rules[0].HTTP.Paths[0].Backend = networkingv1.IngressBackend{
		Resource: &corev1.TypedLocalObjectReference{Kind: "StorageBucket", Name: "assets"},
	}
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if !plan.Fatal() {
		t.Fatalf("resource backend was accepted: %#v", plan)
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
		return map[string]string{
			"Authorization": "$http_authorization",
			"Content-Type":  "application/json",
			"host":          "authgw.zyno.dev",
		}, nil
	}
	plan := Translate(context.Background(), ing, testOptions(), nil, resolver)
	if plan.Fatal() || len(plan.SnippetsFilters) != 1 {
		t.Fatalf("auth proxy headers were not translated: %#v", plan)
	}
	got := plan.SnippetsFilters[0].Spec.Snippets[0].Value
	if !strings.Contains(got, "proxy_set_header Authorization $http_authorization;") {
		t.Fatalf("generated auth location does not contain ConfigMap header:\n%s", got)
	}
	overrideContentType := strings.Index(got, "proxy_set_header Content-Type application/json;")
	overrideHost := strings.Index(got, "proxy_set_header Host authgw.zyno.dev;")
	if strings.Contains(got, "proxy_set_header Content-Type \"\";") || overrideHost < 0 || overrideContentType < overrideHost {
		t.Fatalf("generated auth location does not preserve and override request headers:\n%s", got)
	}
	if strings.Contains(got, "proxy_set_header Host $http_host;") || strings.Count(got, "proxy_set_header Host ") != 1 {
		t.Fatalf("generated auth location contains duplicate Host headers:\n%s", got)
	}

	duplicatePlan := Translate(context.Background(), ing, testOptions(), nil, func(context.Context, string, string) (map[string]string, error) {
		return map[string]string{"Host": "auth.example.com", "host": "other.example.com"}, nil
	})
	if !duplicatePlan.Fatal() {
		t.Fatalf("case-insensitive duplicate auth proxy headers were accepted: %#v", duplicatePlan)
	}
}

func TestTranslateExternalAuthDefaultsAndValidation(t *testing.T) {
	ing := testIngress(map[string]string{annAuthURL: "http://auth.apps.svc.cluster.local:8080/validate"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.SnippetsFilters) != 1 {
		t.Fatalf("default external auth was not translated: %#v", plan)
	}
	got := plan.SnippetsFilters[0].Spec.Snippets[0].Value
	if !strings.Contains(got, "proxy_set_header X-Auth-Request-Redirect $request_uri;") || strings.Contains(got, "proxy_method ") {
		t.Fatalf("generated auth location does not use ingress-nginx defaults:\n%s", got)
	}

	for annotation, value := range map[string]string{
		annAuthMethod:          "post",
		annAuthRequestRedirect: "$request_uri; return 200",
	} {
		invalid := testIngress(map[string]string{annAuthURL: "http://auth.apps.svc.cluster.local:8080/validate", annotation: value})
		invalidPlan := Translate(context.Background(), invalid, testOptions(), nil, nil)
		if !invalidPlan.Fatal() {
			t.Fatalf("unsafe %s value was accepted: %#v", annotation, invalidPlan)
		}
		if len(invalidPlan.Issues) != 1 || invalidPlan.Issues[0].Field != annotation {
			t.Fatalf("unsafe %s value was attributed to the wrong annotation: %#v", annotation, invalidPlan.Issues)
		}
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

func TestTranslateUnverifiedHTTPSBackend(t *testing.T) {
	ing := testIngress(map[string]string{annBackendProtocol: "HTTPS"})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() {
		t.Fatalf("unverified HTTPS backend was rejected: %#v", plan.Issues)
	}
	if len(plan.BackendTLSPolicies) != 0 || len(plan.SnippetsFilters) != 1 {
		t.Fatalf("unexpected HTTPS translation objects: %#v", plan)
	}
	got := plan.SnippetsFilters[0].Spec.Snippets[0].Value
	if !strings.Contains(got, "proxy_pass https://app.apps.svc:8080;") {
		t.Fatalf("unverified HTTPS snippet does not select the Kubernetes Service:\n%s", got)
	}
	if strings.Contains(got, "proxy_ssl_verify") || strings.Contains(got, "proxy_ssl_server_name") {
		t.Fatalf("default ingress-nginx TLS verification/SNI behavior was not preserved:\n%s", got)
	}
	filters := plan.HTTPRoutes[0].Spec.Rules[0].Filters
	if len(filters) == 0 || filters[len(filters)-1].ExtensionRef == nil || filters[len(filters)-1].ExtensionRef.Kind != "SnippetsFilter" {
		t.Fatalf("HTTPS SnippetsFilter was not attached to its route rule: %#v", filters)
	}
}

func TestTranslateUnverifiedHTTPSBackendWithSNI(t *testing.T) {
	ing := testIngress(map[string]string{
		annBackendProtocol:    "HTTPS",
		annProxySSLServerName: "on",
		annProxySSLName:       "backend.example.com",
	})
	plan := Translate(context.Background(), ing, testOptions(), nil, nil)
	if plan.Fatal() || len(plan.SnippetsFilters) != 1 {
		t.Fatalf("unverified HTTPS backend with SNI was not translated: %#v", plan)
	}
	got := plan.SnippetsFilters[0].Spec.Snippets[0].Value
	for _, expected := range []string{"proxy_ssl_server_name on;", "proxy_ssl_name backend.example.com;"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("HTTPS snippet does not contain %q:\n%s", expected, got)
		}
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

func TestCaptureRewriteOverridesPrefixPathType(t *testing.T) {
	ing := testIngress(map[string]string{annRewriteTarget: "/$1"})
	prefix := networkingv1.PathTypePrefix
	ing.Spec.Rules[0].HTTP.Paths[0].Path = `/secret/(.+)`
	ing.Spec.Rules[0].HTTP.Paths[0].PathType = &prefix
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

func TestManagedGatewayCanAllowSameNamespaceListenerSets(t *testing.T) {
	plan := BuildManagedGateway(nil, ManagedGatewayOptions{
		Namespace: "gateway", Name: "public", ClassName: "nginx", AllowListenerSets: true,
		HTTPSectionName: "http", HTTPSSectionName: "https",
	})
	if plan.Gateway.Spec.AllowedListeners == nil || plan.Gateway.Spec.AllowedListeners.Namespaces == nil ||
		plan.Gateway.Spec.AllowedListeners.Namespaces.From == nil {
		t.Fatal("managed Gateway does not allow ListenerSets")
	}
	if got := *plan.Gateway.Spec.AllowedListeners.Namespaces.From; got != gatewayv1.NamespacesFromSame {
		t.Fatalf("ListenerSet namespaces = %q, want %q", got, gatewayv1.NamespacesFromSame)
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
	options.Gateway.TLSSections = plan.TLSSections
	translated := Translate(context.Background(), ing, options, nil, nil)
	if translated.Fatal() {
		t.Fatalf("plan unexpectedly fatal: %#v", translated.Issues)
	}
	wantSection := plan.TLSSections["app.zyno.io"]
	if got := string(*translated.HTTPRoutes[0].Spec.ParentRefs[0].SectionName); got != wantSection {
		t.Fatalf("listener = %q, want %q", got, wantSection)
	}
}

func TestManagedGatewayUsesHostnameScopedTLSListeners(t *testing.T) {
	first := testIngress(nil)
	second := testIngress(nil)
	second.Name = "second"
	second.UID = "second-uid"
	second.Spec.Rules[0].Host = "other.zyno.io"
	second.Spec.TLS[0].Hosts = []string{"other.zyno.io"}
	second.Spec.TLS[0].SecretName = "other-tls"
	plan := BuildManagedGateway([]networkingv1.Ingress{*first, *second}, ManagedGatewayOptions{
		Namespace: "gateway", Name: "public", ClassName: "nginx", HTTPSectionName: "http", HTTPSSectionName: "https",
	})
	if got := len(plan.Gateway.Spec.Listeners); got != 3 {
		t.Fatalf("listeners = %d, want HTTP plus two hostname-scoped HTTPS listeners", got)
	}
	for _, host := range []string{"app.zyno.io", "other.zyno.io"} {
		section := plan.TLSSections[host]
		if section == "" {
			t.Fatalf("missing TLS section for %s", host)
		}
		found := false
		for _, listener := range plan.Gateway.Spec.Listeners {
			if string(listener.Name) == section && listener.Hostname != nil && string(*listener.Hostname) == host && len(listener.TLS.CertificateRefs) == 1 {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing hostname-scoped listener for %s", host)
		}
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
