// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	ngfv1alpha1 "github.com/nginx/nginx-gateway-fabric/v2/apis/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/naming"
)

var (
	nginxSizePattern     = regexp.MustCompile(`^[0-9]{1,4}(k|m|g)?$`)
	nginxDurationPattern = regexp.MustCompile(`^[0-9]{1,4}(ms|s|m|h)?$`)
	nginxUnsafePattern   = regexp.MustCompile(`[\r\n;{}]`)
	nginxVariablePattern = regexp.MustCompile(`[^a-z0-9_]`)
)

// PortResolver resolves a named Service port to its numeric value.
type PortResolver func(ctx context.Context, namespace, service, portName string) (int32, error)

// ConfigMapResolver reads data used by ingress-nginx's *-set-headers annotations.
type ConfigMapResolver func(ctx context.Context, namespace, name string) (map[string]string, error)

type backendTLSConfig struct {
	verified   bool
	secretName string
	hostname   string
	serverName bool
}

type hostInput struct {
	hostname       string
	paths          []networkingv1.HTTPIngressPath
	tlsHostname    string
	tlsSectionName string
}

type canaryHostInput struct {
	ingress networkingv1.Ingress
	input   hostInput
}

// Translate converts one Ingress into same-namespace Gateway API and NGF objects.
func Translate(
	ctx context.Context,
	ing *networkingv1.Ingress,
	options Options,
	resolvePort PortResolver,
	resolveConfigMap ConfigMapResolver,
) Plan {
	plan := Plan{}
	checkUnknownAnnotations(ing, options.Strict, &plan)
	plan.Issues = append(plan.Issues, ValidateCanary(ing)...)

	protocol := strings.ToUpper(strings.TrimSpace(ing.Annotations[annBackendProtocol]))
	if protocol == "" {
		protocol = "HTTP"
	}
	var backendTLS *backendTLSConfig
	if protocol == "HTTPS" {
		var issues []Issue
		backendTLS, issues = parseBackendTLS(ing)
		plan.Issues = append(plan.Issues, issues...)
	} else if protocol != "HTTP" {
		plan.Issues = append(plan.Issues, Issue{
			Severity: SeverityError,
			Field:    annBackendProtocol,
			Message:  fmt.Sprintf("backend protocol %q cannot be reproduced by the current NGF translation", protocol),
		})
	}
	if version := strings.TrimSpace(ing.Annotations[annProxyHTTPVersion]); version != "" && version != "1.1" {
		plan.Issues = append(plan.Issues, Issue{
			Severity: SeverityError,
			Field:    annProxyHTTPVersion,
			Message:  fmt.Sprintf("NGF uses upstream HTTP/1.1; proxy HTTP version %q is not supported", version),
		})
	}

	authProxyHeaders := resolveAuthProxyHeaders(ctx, ing, resolveConfigMap, &plan)

	canariesByHost := make(map[string][]canaryHostInput)
	canaryFootprints := make(map[string]string)
	for idx := range options.CanaryIngresses {
		plan.Issues = append(plan.Issues, ValidateCanary(&options.CanaryIngresses[idx])...)
		canary := inheritedCanaryIngress(ing, &options.CanaryIngresses[idx])
		for _, input := range collectHosts(&canary, options, &plan) {
			for _, path := range input.paths {
				pathValue := path.Path
				if pathValue == "" {
					pathValue = "/"
				}
				footprint := input.hostname + "\x00" + pathValue
				if existing, found := canaryFootprints[footprint]; found && existing != canary.Name {
					plan.Issues = append(plan.Issues, Issue{
						Severity: SeverityError,
						Field:    annCanary,
						Message:  fmt.Sprintf("canary Ingresses %s and %s target the same hostname and path; ingress-nginx permits only one canary per rule", existing, canary.Name),
					})
				} else {
					canaryFootprints[footprint] = canary.Name
				}
			}
			canariesByHost[input.hostname] = append(canariesByHost[input.hostname], canaryHostInput{
				ingress: canary,
				input:   input,
			})
		}
	}

	inputs := collectHosts(ing, options, &plan)
	for _, input := range inputs {
		route, routeIssues, locationSnippets := buildRoute(ctx, ing, input, options, resolvePort)
		plan.Issues = append(plan.Issues, routeIssues...)
		for _, canary := range canariesByHost[input.hostname] {
			for _, path := range canary.input.paths {
				rule, ruleIssues, _ := buildRule(ctx, &canary.ingress, path, len(route.Spec.Rules), resolvePort)
				plan.Issues = append(plan.Issues, ruleIssues...)
				route.Spec.Rules = append(route.Spec.Rules, rule)
			}
		}
		if len(route.Spec.Rules) > 16 {
			plan.Issues = append(plan.Issues, Issue{
				Severity: SeverityError,
				Field:    "spec.rules.paths",
				Message:  "a generated HTTPRoute cannot contain more than 16 primary and canary rules",
			})
		}
		plan.HTTPRoutes = append(plan.HTTPRoutes, route)

		addPolicies(ing, &route, locationSnippets, authProxyHeaders, backendTLS, options, &plan)
		plan.HTTPRoutes[len(plan.HTTPRoutes)-1] = route

		if input.tlsHostname != "" && sslRedirectEnabled(ing.Annotations) && !parseBool(ing.Annotations[annCanary]) {
			plan.HTTPRoutes = append(plan.HTTPRoutes, buildRedirectRoute(ing, input.hostname, options))
		}
	}

	return plan
}

func inheritedCanaryIngress(primary, canary *networkingv1.Ingress) networkingv1.Ingress {
	effective := *canary.DeepCopy()
	effective.Annotations = make(map[string]string, len(primary.Annotations)+3)
	for key, value := range primary.Annotations {
		effective.Annotations[key] = value
	}
	for _, annotation := range []string{annCanary, annCanaryByHeader, annCanaryByHeaderValue} {
		if value, exists := canary.Annotations[annotation]; exists {
			effective.Annotations[annotation] = value
		} else {
			delete(effective.Annotations, annotation)
		}
	}
	return effective
}

// ValidateCanary reports whether an Ingress uses the header/value canary mode
// that the bridge can reproduce faithfully.
func ValidateCanary(ing *networkingv1.Ingress) []Issue {
	if !parseBool(ing.Annotations[annCanary]) {
		return nil
	}
	_, issues := headerCanaryMatch(ing.Annotations)
	if ing.Spec.DefaultBackend != nil {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Field:    "spec.defaultBackend",
			Message:  "a canary cannot be used as a catch-all default backend",
		})
	}
	return issues
}

func headerCanaryMatch(annotations map[string]string) (*gatewayv1.HTTPHeaderMatch, []Issue) {
	header := strings.TrimSpace(annotations[annCanaryByHeader])
	value := strings.TrimSpace(annotations[annCanaryByHeaderValue])
	if header == "" || value == "" {
		return nil, []Issue{{
			Severity: SeverityError,
			Field:    annCanary,
			Message:  "only header/value canaries are currently supported; both canary-by-header and canary-by-header-value are required",
		}}
	}
	if !validHeaderName(header) {
		return nil, []Issue{{Severity: SeverityError, Field: annCanaryByHeader, Message: "invalid HTTP header name"}}
	}
	headerType := gatewayv1.HeaderMatchExact
	return &gatewayv1.HTTPHeaderMatch{
		Type: &headerType, Name: gatewayv1.HTTPHeaderName(header), Value: value,
	}, nil
}

func checkUnknownAnnotations(ing *networkingv1.Ingress, strict bool, plan *Plan) {
	for key := range ing.Annotations {
		if !strings.HasPrefix(key, annotationPrefix) {
			continue
		}
		if _, ok := knownAnnotations[key]; ok {
			continue
		}
		severity := SeverityWarning
		if strict {
			severity = SeverityError
		}
		plan.Issues = append(plan.Issues, Issue{
			Severity: severity,
			Field:    key,
			Message:  "annotation has no declared compatibility translation",
		})
	}
}

func parseBackendTLS(ing *networkingv1.Ingress) (*backendTLSConfig, []Issue) {
	var issues []Issue
	verify := false
	if raw := strings.TrimSpace(ing.Annotations[annProxySSLVerify]); raw != "" {
		var err error
		verify, err = parseNginxBool(raw)
		if err != nil {
			issues = append(issues, Issue{Severity: SeverityError, Field: annProxySSLVerify, Message: err.Error()})
		}
	}
	serverNameEnabled := false
	if raw := strings.TrimSpace(ing.Annotations[annProxySSLServerName]); raw != "" {
		var err error
		serverNameEnabled, err = parseNginxBool(raw)
		if err != nil {
			issues = append(issues, Issue{Severity: SeverityError, Field: annProxySSLServerName, Message: err.Error()})
		}
	}
	hostname := strings.TrimSpace(ing.Annotations[annProxySSLName])
	if hostname != "" && len(k8svalidation.IsDNS1123Subdomain(hostname)) > 0 {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Field:    annProxySSLName,
			Message:  "proxy-ssl-name must contain a valid DNS hostname",
		})
	}

	secretRef := strings.TrimSpace(ing.Annotations[annProxySSLSecret])
	if !verify {
		if secretRef != "" {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Field:    annProxySSLSecret,
				Message:  "proxy-ssl-secret with verification disabled may configure an upstream client certificate, which is not supported yet",
			})
		}
		if len(issues) > 0 {
			return nil, issues
		}
		return &backendTLSConfig{verified: false, hostname: hostname, serverName: serverNameEnabled}, nil
	}

	if !serverNameEnabled {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Field:    annProxySSLServerName,
			Message:  "HTTPS backends require proxy-ssl-server-name: on",
		})
	}
	if errs := k8svalidation.IsDNS1123Subdomain(hostname); hostname == "" || len(errs) > 0 {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Field:    annProxySSLName,
			Message:  "HTTPS backends require proxy-ssl-name containing a valid DNS hostname",
		})
	}

	secretName := secretRef
	if parts := strings.SplitN(secretRef, "/", 2); len(parts) == 2 {
		if parts[0] != ing.Namespace {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Field:    annProxySSLSecret,
				Message:  "BackendTLSPolicy CA references must be in the Ingress namespace",
			})
		}
		secretName = parts[1]
	}
	if secretName == "" || len(k8svalidation.IsDNS1123Subdomain(secretName)) > 0 {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Field:    annProxySSLSecret,
			Message:  "HTTPS backends require proxy-ssl-secret referencing a Secret containing ca.crt",
		})
	}
	if len(issues) > 0 {
		return nil, issues
	}
	return &backendTLSConfig{verified: true, secretName: secretName, hostname: hostname, serverName: true}, nil
}

func resolveAuthProxyHeaders(
	ctx context.Context,
	ing *networkingv1.Ingress,
	resolve ConfigMapResolver,
	plan *Plan,
) map[string]string {
	reference := strings.TrimSpace(ing.Annotations[annAuthProxySetHeaders])
	if reference == "" {
		return nil
	}
	if strings.TrimSpace(ing.Annotations[annAuthURL]) == "" {
		plan.Issues = append(plan.Issues, Issue{
			Severity: SeverityError, Field: annAuthProxySetHeaders, Message: "auth-proxy-set-headers requires auth-url",
		})
		return nil
	}
	name := reference
	if parts := strings.SplitN(reference, "/", 2); len(parts) == 2 {
		if parts[0] != ing.Namespace {
			plan.Issues = append(plan.Issues, Issue{
				Severity: SeverityError, Field: annAuthProxySetHeaders, Message: "auth proxy header ConfigMap must be in the Ingress namespace",
			})
			return nil
		}
		name = parts[1]
	}
	if resolve == nil {
		plan.Issues = append(plan.Issues, Issue{
			Severity: SeverityError, Field: annAuthProxySetHeaders, Message: "no ConfigMap resolver is configured",
		})
		return nil
	}
	headers, err := resolve(ctx, ing.Namespace, name)
	if err != nil {
		plan.Issues = append(plan.Issues, Issue{
			Severity: SeverityError, Field: annAuthProxySetHeaders, Message: fmt.Sprintf("read ConfigMap %s/%s: %v", ing.Namespace, name, err),
		})
		return nil
	}
	return headers
}

func collectHosts(ing *networkingv1.Ingress, options Options, plan *Plan) []hostInput {
	tlsHosts := options.TLSHosts
	if tlsHosts == nil {
		tlsHosts = make(map[string]struct{})
		for _, tls := range ing.Spec.TLS {
			hosts := effectiveTLSHosts(ing, tls)
			if len(hosts) == 0 {
				plan.Issues = append(plan.Issues, Issue{
					Severity: SeverityError,
					Field:    "spec.tls.hosts",
					Message:  "TLS entry has no hosts and the Ingress has no named rules from which to infer them",
				})
			}
			for _, host := range hosts {
				tlsHosts[host] = struct{}{}
			}
		}
	}

	byHost := make(map[string][]networkingv1.HTTPIngressPath)
	ordered := make([]string, 0, len(ing.Spec.Rules))
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			plan.Issues = append(plan.Issues, Issue{
				Severity: SeverityError,
				Field:    "spec.rules",
				Message:  fmt.Sprintf("host %q does not contain an HTTP rule", rule.Host),
			})
			continue
		}
		host := strings.ToLower(strings.TrimSpace(rule.Host))
		if _, exists := byHost[host]; !exists {
			ordered = append(ordered, host)
		}
		byHost[host] = append(byHost[host], rule.HTTP.Paths...)
	}

	if ing.Spec.DefaultBackend != nil {
		_, existed := byHost[""]
		pathType := networkingv1.PathTypePrefix
		byHost[""] = append(byHost[""], networkingv1.HTTPIngressPath{
			Path:     "/",
			PathType: &pathType,
			Backend:  *ing.Spec.DefaultBackend,
		})
		if !existed {
			ordered = append(ordered, "")
		}
	}
	if len(ordered) == 0 {
		plan.Issues = append(plan.Issues, Issue{
			Severity: SeverityError,
			Field:    "spec",
			Message:  "Ingress has neither HTTP rules nor a default backend",
		})
	}

	aliases := splitCSV(ing.Annotations[annServerAlias])
	if len(aliases) > 0 {
		if len(ordered) == 0 {
			plan.Issues = append(plan.Issues, Issue{
				Severity: SeverityError,
				Field:    annServerAlias,
				Message:  "server aliases require at least one HTTP rule",
			})
		} else {
			basePaths := byHost[ordered[0]]
			for _, alias := range aliases {
				alias = strings.ToLower(alias)
				if _, exists := byHost[alias]; exists {
					continue
				}
				ordered = append(ordered, alias)
				byHost[alias] = append([]networkingv1.HTTPIngressPath(nil), basePaths...)
				if coveredBy := matchingTLSHost(alias, tlsHosts); coveredBy == "" && len(ing.Spec.TLS) > 0 {
					plan.Issues = append(plan.Issues, Issue{
						Severity: SeverityWarning,
						Field:    annServerAlias,
						Message:  fmt.Sprintf("alias %q is not listed in spec.tls.hosts and will only attach to HTTP", alias),
					})
				}
			}
		}
	}

	result := make([]hostInput, 0, len(ordered))
	for _, host := range ordered {
		tlsHostname := matchingTLSHost(host, tlsHosts)
		tlsSectionName := options.Gateway.HTTPSSectionName
		if section, exists := options.Gateway.TLSSections[tlsHostname]; exists {
			tlsSectionName = section
		}
		result = append(result, hostInput{
			hostname: host, paths: byHost[host], tlsHostname: tlsHostname, tlsSectionName: tlsSectionName,
		})
	}
	return result
}

func buildRoute(
	ctx context.Context,
	ing *networkingv1.Ingress,
	input hostInput,
	options Options,
	resolvePort PortResolver,
) (gatewayv1.HTTPRoute, []Issue, []string) {
	name := naming.DNSLabel(ing.Name, hostNamePart(input.hostname))
	route := gatewayv1.HTTPRoute{
		TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "HTTPRoute"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ing.Namespace,
			Labels:    sourceLabels(ing),
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: applicationParentRefs(
					ing.Namespace,
					input,
					options.Gateway,
					input.tlsHostname != "" && !sslRedirectEnabled(ing.Annotations),
				),
			},
		},
	}
	if input.hostname != "" {
		route.Spec.Hostnames = []gatewayv1.Hostname{gatewayv1.Hostname(input.hostname)}
	}

	var issues []Issue
	var locationSnippets []string
	if parseBool(ing.Annotations[annEnableCORS]) {
		locationSnippets = append(locationSnippets, corsUpstreamHeaderSuppressionSnippet)
	}
	if len(input.paths) > 16 {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Field:    "spec.rules.paths",
			Message:  "a generated HTTPRoute cannot contain more than 16 rules",
		})
	}
	for idx, path := range input.paths {
		rule, ruleIssues, rewriteSnippet := buildRule(ctx, ing, path, idx, resolvePort)
		issues = append(issues, ruleIssues...)
		if rewriteSnippet != "" {
			locationSnippets = append(locationSnippets, rewriteSnippet)
		}
		route.Spec.Rules = append(route.Spec.Rules, rule)
	}
	return route, issues, locationSnippets
}

func buildRule(
	ctx context.Context,
	ing *networkingv1.Ingress,
	path networkingv1.HTTPIngressPath,
	index int,
	resolvePort PortResolver,
) (gatewayv1.HTTPRouteRule, []Issue, string) {
	var issues []Issue
	pathValue := path.Path
	if pathValue == "" {
		pathValue = "/"
	}
	matchType := gatewayv1.PathMatchPathPrefix
	if path.PathType != nil {
		switch *path.PathType {
		case networkingv1.PathTypeExact:
			matchType = gatewayv1.PathMatchExact
		case networkingv1.PathTypePrefix:
			matchType = gatewayv1.PathMatchPathPrefix
		case networkingv1.PathTypeImplementationSpecific:
		}
	}
	// ingress-nginx renders capture-group rewrite locations as regular
	// expressions even when the Ingress declares pathType: Prefix. Preserve
	// that behavior so the generated rewrite snippet is actually reachable.
	if parseBool(ing.Annotations[annUseRegex]) || strings.Contains(ing.Annotations[annRewriteTarget], "$") {
		matchType = gatewayv1.PathMatchRegularExpression
	}

	match := gatewayv1.HTTPRouteMatch{
		Path: &gatewayv1.HTTPPathMatch{Type: &matchType, Value: &pathValue},
	}
	if parseBool(ing.Annotations[annCanary]) {
		headerMatch, _ := headerCanaryMatch(ing.Annotations)
		if headerMatch != nil {
			match.Headers = []gatewayv1.HTTPHeaderMatch{*headerMatch}
		}
	}

	port, err := backendPort(ctx, ing.Namespace, path.Backend.Service, resolvePort)
	if err != nil {
		issues = append(issues, Issue{Severity: SeverityError, Field: fmt.Sprintf("spec.rules.paths[%d].backend", index), Message: err.Error()})
	}
	backendName := gatewayv1.ObjectName("")
	if path.Backend.Service != nil {
		backendName = gatewayv1.ObjectName(path.Backend.Service.Name)
	}
	rule := gatewayv1.HTTPRouteRule{
		Matches: []gatewayv1.HTTPRouteMatch{match},
		BackendRefs: []gatewayv1.HTTPBackendRef{{
			BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{
				Name: backendName, Port: ptr(gatewayv1.PortNumber(port)),
			}},
		}},
	}

	if cors, corsIssues := corsFilter(ing.Annotations); cors != nil {
		rule.Filters = append(rule.Filters, gatewayv1.HTTPRouteFilter{Type: gatewayv1.HTTPRouteFilterCORS, CORS: cors})
		issues = append(issues, corsIssues...)
	} else {
		issues = append(issues, corsIssues...)
	}
	var rewriteSnippet string
	if target := strings.TrimSpace(ing.Annotations[annRewriteTarget]); target != "" {
		if strings.Contains(target, "$") {
			if err := validateGeneratedRewrite(pathValue, target); err != nil {
				issues = append(issues, Issue{Severity: SeverityError, Field: annRewriteTarget, Message: err.Error()})
			} else {
				rewriteSnippet = fmt.Sprintf("rewrite %s %s break;", pathValue, target)
			}
		} else if strings.HasPrefix(target, "/") {
			rule.Filters = append(rule.Filters, gatewayv1.HTTPRouteFilter{
				Type: gatewayv1.HTTPRouteFilterURLRewrite,
				URLRewrite: &gatewayv1.HTTPURLRewriteFilter{Path: &gatewayv1.HTTPPathModifier{
					Type: gatewayv1.FullPathHTTPPathModifier, ReplaceFullPath: &target,
				}},
			})
		} else {
			issues = append(issues, Issue{Severity: SeverityError, Field: annRewriteTarget, Message: "rewrite target must be an absolute path"})
		}
	}

	return rule, issues, rewriteSnippet
}

const corsUpstreamHeaderSuppressionSnippet = `proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Credentials;
proxy_hide_header Access-Control-Allow-Methods;
proxy_hide_header Access-Control-Allow-Headers;
proxy_hide_header Access-Control-Expose-Headers;
proxy_hide_header Access-Control-Max-Age;`

func addPolicies(
	ing *networkingv1.Ingress,
	route *gatewayv1.HTTPRoute,
	generatedLocationSnippets []string,
	authProxyHeaders map[string]string,
	backendTLS *backendTLSConfig,
	options Options,
	plan *Plan,
) {
	labels := sourceLabels(ing)
	target := gatewayv1.LocalPolicyTargetReference{
		Group: gatewayv1.Group(gatewayv1.GroupVersion.Group), Kind: "HTTPRoute", Name: gatewayv1.ObjectName(route.Name),
	}

	plan.Issues = append(plan.Issues, addUpstreamVHostFilter(ing, route)...)

	if options.SettingsAsSnippets {
		settingsSnippets, settingsIssues := buildProxySettingsSnippets(ing)
		generatedLocationSnippets = append(generatedLocationSnippets, settingsSnippets...)
		plan.Issues = append(plan.Issues, settingsIssues...)
		if value := strings.ToLower(strings.TrimSpace(ing.Annotations[annProxyBodySize])); value != "" {
			if !nginxSizePattern.MatchString(value) {
				plan.Issues = append(plan.Issues, Issue{Severity: SeverityError, Field: annProxyBodySize, Message: "value is not supported by NGINX client_max_body_size"})
			} else {
				plan.Issues = append(plan.Issues, Issue{
					Severity: SeverityError,
					Field:    annProxyBodySize,
					Message:  "proxy-body-size cannot be applied faithfully to overlapping non-canary routes; consolidate the routes into one HTTPRoute",
				})
			}
		}
	} else if value := strings.ToLower(strings.TrimSpace(ing.Annotations[annProxyBodySize])); value != "" {
		if !nginxSizePattern.MatchString(value) {
			plan.Issues = append(plan.Issues, Issue{Severity: SeverityError, Field: annProxyBodySize, Message: "value is not supported by NGF ClientSettingsPolicy"})
		} else {
			size := ngfv1alpha1.Size(value)
			plan.ClientSettingsPolicies = append(plan.ClientSettingsPolicies, ngfv1alpha1.ClientSettingsPolicy{
				TypeMeta:   metav1.TypeMeta{APIVersion: ngfv1alpha1.SchemeGroupVersion.String(), Kind: "ClientSettingsPolicy"},
				ObjectMeta: metav1.ObjectMeta{Name: naming.DNSLabel(route.Name, "client"), Namespace: ing.Namespace, Labels: labels},
				Spec:       ngfv1alpha1.ClientSettingsPolicySpec{TargetRef: target, Body: &ngfv1alpha1.ClientBody{MaxSize: &size}},
			})
		}
	}

	if !options.SettingsAsSnippets {
		proxyPolicy, proxyIssues := buildProxyPolicy(ing, route.Name, target, labels)
		plan.Issues = append(plan.Issues, proxyIssues...)
		if proxyPolicy != nil {
			plan.ProxySettingsPolicies = append(plan.ProxySettingsPolicies, *proxyPolicy)
		}
	}
	if backendTLS != nil && backendTLS.verified {
		for _, policy := range buildBackendTLSPolicies(ing, route, *backendTLS) {
			duplicate := false
			for _, existing := range plan.BackendTLSPolicies {
				if existing.Namespace == policy.Namespace && existing.Name == policy.Name {
					duplicate = true
					break
				}
			}
			if !duplicate {
				plan.BackendTLSPolicies = append(plan.BackendTLSPolicies, policy)
			}
		}
	}
	if backendTLS != nil && !backendTLS.verified {
		addUnverifiedBackendTLSFilters(ing, route, *backendTLS, labels, plan)
	}

	authFilter, authIssues := buildBasicAuth(ing, route.Name, labels)
	plan.Issues = append(plan.Issues, authIssues...)
	if authFilter != nil {
		plan.AuthenticationFilters = append(plan.AuthenticationFilters, *authFilter)
		appendExtensionFilter(route, "AuthenticationFilter", authFilter.Name)
	}

	snippetFilter, snippetIssues := buildSnippets(
		ing, route.Name, generatedLocationSnippets, authProxyHeaders, options.AllowSnippets, labels,
	)
	plan.Issues = append(plan.Issues, snippetIssues...)
	if snippetFilter != nil {
		plan.SnippetsFilters = append(plan.SnippetsFilters, *snippetFilter)
		appendExtensionFilter(route, "SnippetsFilter", snippetFilter.Name)
	}
}

func addUpstreamVHostFilter(ing *networkingv1.Ingress, route *gatewayv1.HTTPRoute) []Issue {
	host := strings.TrimSpace(ing.Annotations[annUpstreamVHost])
	if host == "" {
		return nil
	}
	if nginxUnsafePattern.MatchString(host) || strings.ContainsAny(host, " \t") {
		return []Issue{{
			Severity: SeverityError,
			Field:    annUpstreamVHost,
			Message:  "value contains characters unsafe for the upstream Host header",
		}}
	}

	for idx := range route.Spec.Rules {
		route.Spec.Rules[idx].Filters = append(route.Spec.Rules[idx].Filters, gatewayv1.HTTPRouteFilter{
			Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
			RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
				Set: []gatewayv1.HTTPHeader{{
					Name:  gatewayv1.HTTPHeaderName("Host"),
					Value: host,
				}},
			},
		})
	}
	return nil
}

func addUnverifiedBackendTLSFilters(
	ing *networkingv1.Ingress,
	route *gatewayv1.HTTPRoute,
	config backendTLSConfig,
	labels map[string]string,
	plan *Plan,
) {
	for idx := range route.Spec.Rules {
		rule := &route.Spec.Rules[idx]
		if len(rule.BackendRefs) != 1 || rule.BackendRefs[0].Port == nil {
			plan.Issues = append(plan.Issues, Issue{
				Severity: SeverityError,
				Field:    fmt.Sprintf("spec.rules[%d].backendRefs", idx),
				Message:  "unverified HTTPS translation requires exactly one Service backend with a numeric port",
			})
			continue
		}

		backend := rule.BackendRefs[0]
		serviceAddress := fmt.Sprintf("%s.%s.svc:%d", backend.Name, route.Namespace, *backend.Port)
		requestURI := ""
		if ruleNeedsOriginalRequestURI(*rule) && strings.TrimSpace(ing.Annotations[annRewriteTarget]) == "" {
			requestURI = "$request_uri"
		}

		location := make([]string, 0, 3)
		if config.serverName {
			location = append(location, "proxy_ssl_server_name on;")
		}
		if config.hostname != "" {
			location = append(location, "proxy_ssl_name "+config.hostname+";")
		}
		location = append(location, fmt.Sprintf(
			"if ($request_method) {\n  proxy_pass https://%s%s;\n}",
			serviceAddress,
			requestURI,
		))

		filter := ngfv1alpha1.SnippetsFilter{
			TypeMeta: metav1.TypeMeta{APIVersion: ngfv1alpha1.SchemeGroupVersion.String(), Kind: "SnippetsFilter"},
			ObjectMeta: metav1.ObjectMeta{
				Name: naming.DNSLabel(route.Name, "backend-https", strconv.Itoa(idx)), Namespace: ing.Namespace, Labels: labels,
			},
			Spec: ngfv1alpha1.SnippetsFilterSpec{Snippets: []ngfv1alpha1.Snippet{{
				Context: ngfv1alpha1.NginxContextHTTPServerLocation,
				Value:   strings.Join(location, "\n") + "\n",
			}}},
		}
		plan.SnippetsFilters = append(plan.SnippetsFilters, filter)
		appendExtensionFilterToRule(rule, "SnippetsFilter", filter.Name)
	}
}

func ruleNeedsOriginalRequestURI(rule gatewayv1.HTTPRouteRule) bool {
	if len(rule.Matches) != 1 {
		return true
	}
	match := rule.Matches[0]
	return match.Method != nil || len(match.Headers) > 0 || len(match.QueryParams) > 0
}

func buildProxySettingsSnippets(ing *networkingv1.Ingress) ([]string, []Issue) {
	var snippets []string
	var issues []Issue
	for _, setting := range []struct {
		annotation string
		directive  string
	}{
		{annotation: annProxyConnectTimeout, directive: "proxy_connect_timeout"},
		{annotation: annProxyReadTimeout, directive: "proxy_read_timeout"},
		{annotation: annProxySendTimeout, directive: "proxy_send_timeout"},
	} {
		if raw := strings.TrimSpace(ing.Annotations[setting.annotation]); raw != "" {
			value, err := normalizeDuration(raw)
			if err != nil {
				issues = append(issues, Issue{Severity: SeverityError, Field: setting.annotation, Message: err.Error()})
			} else {
				snippets = append(snippets, setting.directive+" "+value+";")
			}
		}
	}
	if raw := strings.TrimSpace(ing.Annotations[annProxyBuffering]); raw != "" {
		enabled, err := parseNginxBool(raw)
		if err != nil {
			issues = append(issues, Issue{Severity: SeverityError, Field: annProxyBuffering, Message: err.Error()})
		} else if enabled {
			snippets = append(snippets, "proxy_buffering on;")
		} else {
			snippets = append(snippets, "proxy_buffering off;")
		}
	}
	if value := strings.ToLower(strings.TrimSpace(ing.Annotations[annProxyBufferSize])); value != "" {
		if !nginxSizePattern.MatchString(value) {
			issues = append(issues, Issue{Severity: SeverityError, Field: annProxyBufferSize, Message: "value is not supported by NGINX proxy_buffer_size"})
		} else {
			snippets = append(snippets, "proxy_buffer_size "+value+";")
			snippets = append(snippets, "proxy_buffers 4 "+value+";")
		}
	}
	return snippets, issues
}

func buildProxyPolicy(
	ing *networkingv1.Ingress,
	routeName string,
	target gatewayv1.LocalPolicyTargetReference,
	labels map[string]string,
) (*ngfv1alpha1.ProxySettingsPolicy, []Issue) {
	var issues []Issue
	settings := ngfv1alpha1.ProxySettingsPolicySpec{TargetRefs: []gatewayv1.LocalPolicyTargetReference{target}}
	timeout := &ngfv1alpha1.ProxyTimeout{}
	for annotation, destination := range map[string]**ngfv1alpha1.Duration{
		annProxyConnectTimeout: &timeout.Connect,
		annProxyReadTimeout:    &timeout.Read,
		annProxySendTimeout:    &timeout.Send,
	} {
		if raw := strings.TrimSpace(ing.Annotations[annotation]); raw != "" {
			value, err := normalizeDuration(raw)
			if err != nil {
				issues = append(issues, Issue{Severity: SeverityError, Field: annotation, Message: err.Error()})
			} else {
				*destination = ptr(ngfv1alpha1.Duration(value))
			}
		}
	}
	if timeout.Connect != nil || timeout.Read != nil || timeout.Send != nil {
		settings.Timeout = timeout
	}

	buffering := &ngfv1alpha1.ProxyBuffering{}
	if raw := strings.TrimSpace(ing.Annotations[annProxyBuffering]); raw != "" {
		enabled, err := parseNginxBool(raw)
		if err != nil {
			issues = append(issues, Issue{Severity: SeverityError, Field: annProxyBuffering, Message: err.Error()})
		} else {
			buffering.Disable = ptr(!enabled)
		}
	}
	if raw := strings.ToLower(strings.TrimSpace(ing.Annotations[annProxyBufferSize])); raw != "" {
		if !nginxSizePattern.MatchString(raw) {
			issues = append(issues, Issue{Severity: SeverityError, Field: annProxyBufferSize, Message: "value is not supported by NGF ProxySettingsPolicy"})
		} else {
			size := ngfv1alpha1.Size(raw)
			buffering.BufferSize = ptr(size)
			buffering.Buffers = &ngfv1alpha1.ProxyBuffers{Number: 4, Size: size}
		}
	}
	if buffering.Disable != nil || buffering.BufferSize != nil || buffering.Buffers != nil {
		settings.Buffering = buffering
	}
	if settings.Timeout == nil && settings.Buffering == nil {
		return nil, issues
	}
	return &ngfv1alpha1.ProxySettingsPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: ngfv1alpha1.SchemeGroupVersion.String(), Kind: "ProxySettingsPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: naming.DNSLabel(routeName, "proxy"), Namespace: ing.Namespace, Labels: labels},
		Spec:       settings,
	}, issues
}

func buildBackendTLSPolicies(
	ing *networkingv1.Ingress,
	route *gatewayv1.HTTPRoute,
	config backendTLSConfig,
) []gatewayv1.BackendTLSPolicy {
	services := make(map[gatewayv1.ObjectName]struct{})
	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			services[backend.Name] = struct{}{}
		}
	}
	names := make([]string, 0, len(services))
	for service := range services {
		names = append(names, string(service))
	}
	sort.Strings(names)

	policies := make([]gatewayv1.BackendTLSPolicy, 0, len(names))
	for _, service := range names {
		policies = append(policies, gatewayv1.BackendTLSPolicy{
			TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "BackendTLSPolicy"},
			ObjectMeta: metav1.ObjectMeta{
				Name: naming.DNSLabel(ing.Name, service, "backend-tls"), Namespace: ing.Namespace, Labels: sourceLabels(ing),
			},
			Spec: gatewayv1.BackendTLSPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: "", Kind: "Service", Name: gatewayv1.ObjectName(service),
					},
				}},
				Validation: gatewayv1.BackendTLSPolicyValidation{
					CACertificateRefs: []gatewayv1.LocalObjectReference{{
						Group: "", Kind: "Secret", Name: gatewayv1.ObjectName(config.secretName),
					}},
					Hostname: gatewayv1.PreciseHostname(config.hostname),
				},
			},
		})
	}
	return policies
}

func buildBasicAuth(
	ing *networkingv1.Ingress,
	routeName string,
	labels map[string]string,
) (*ngfv1alpha1.AuthenticationFilter, []Issue) {
	typ := strings.ToLower(strings.TrimSpace(ing.Annotations[annAuthType]))
	secret := strings.TrimSpace(ing.Annotations[annAuthSecret])
	if typ == "" && secret == "" {
		return nil, nil
	}
	if ing.Annotations[annAuthURL] != "" {
		return nil, []Issue{{Severity: SeverityError, Field: annAuthType, Message: "basic auth and external auth cannot be enabled on the same Ingress"}}
	}
	if typ != "basic" {
		return nil, []Issue{{Severity: SeverityError, Field: annAuthType, Message: fmt.Sprintf("authentication type %q is not supported", typ)}}
	}
	if secret == "" || strings.Contains(secret, "/") {
		return nil, []Issue{{Severity: SeverityError, Field: annAuthSecret, Message: "auth-secret must name a Secret in the Ingress namespace"}}
	}
	realm := strings.TrimSpace(ing.Annotations[annAuthRealm])
	if realm == "" {
		realm = "Authentication Required"
	}
	return &ngfv1alpha1.AuthenticationFilter{
		TypeMeta:   metav1.TypeMeta{APIVersion: ngfv1alpha1.SchemeGroupVersion.String(), Kind: "AuthenticationFilter"},
		ObjectMeta: metav1.ObjectMeta{Name: naming.DNSLabel(routeName, "basic-auth"), Namespace: ing.Namespace, Labels: labels},
		Spec: ngfv1alpha1.AuthenticationFilterSpec{
			Type:  ngfv1alpha1.AuthTypeBasic,
			Basic: &ngfv1alpha1.BasicAuth{SecretRef: ngfv1alpha1.LocalObjectReference{Name: secret}, Realm: realm},
		},
	}, nil
}

func buildSnippets(
	ing *networkingv1.Ingress,
	routeName string,
	generatedLocationSnippets []string,
	authProxyHeaders map[string]string,
	allowRaw bool,
	labels map[string]string,
) (*ngfv1alpha1.SnippetsFilter, []Issue) {
	var issues []Issue
	var server, location []string
	location = append(location, generatedLocationSnippets...)

	authSnippet := strings.TrimSpace(ing.Annotations[annAuthSnippet])
	if authSnippet != "" {
		if strings.TrimSpace(ing.Annotations[annAuthURL]) == "" {
			issues = append(issues, Issue{Severity: SeverityError, Field: annAuthSnippet, Message: "auth-snippet requires auth-url"})
			authSnippet = ""
		} else if !allowRaw {
			issues = append(issues, Issue{Severity: SeverityError, Field: annAuthSnippet, Message: "raw snippets are disabled; start the controller with --allow-snippets only after reviewing the source"})
			authSnippet = ""
		}
	}

	if raw := strings.TrimSpace(ing.Annotations[annProxyRequestBuffering]); raw != "" {
		enabled, err := parseNginxBool(raw)
		if err != nil {
			issues = append(issues, Issue{Severity: SeverityError, Field: annProxyRequestBuffering, Message: err.Error()})
		} else if !enabled {
			location = append(location, "proxy_request_buffering off;")
		}
	}

	if authURL := strings.TrimSpace(ing.Annotations[annAuthURL]); authURL != "" {
		bodySize := strings.ToLower(strings.TrimSpace(ing.Annotations[annProxyBodySize]))
		if !nginxSizePattern.MatchString(bodySize) {
			bodySize = ""
		}
		authServer, authLocation, err := externalAuthSnippets(
			routeName, authURL, ing.Annotations, authSnippet, authProxyHeaders, bodySize,
		)
		if err != nil {
			issues = append(issues, Issue{Severity: SeverityError, Field: annAuthURL, Message: err.Error()})
		} else {
			server = append(server, authServer)
			location = append(location, authLocation)
		}
	}

	for annotation, context := range map[string]*[]string{
		annServerSnippet:        &server,
		annConfigurationSnippet: &location,
	} {
		if raw := strings.TrimSpace(ing.Annotations[annotation]); raw != "" {
			if !allowRaw {
				issues = append(issues, Issue{Severity: SeverityError, Field: annotation, Message: "raw snippets are disabled; start the controller with --allow-snippets only after reviewing the source"})
			} else {
				*context = append(*context, raw)
			}
		}
	}

	if len(server) == 0 && len(location) == 0 {
		return nil, issues
	}
	snippets := make([]ngfv1alpha1.Snippet, 0, 2)
	if len(server) > 0 {
		snippets = append(snippets, ngfv1alpha1.Snippet{Context: ngfv1alpha1.NginxContextHTTPServer, Value: strings.Join(server, "\n") + "\n"})
	}
	if len(location) > 0 {
		snippets = append(snippets, ngfv1alpha1.Snippet{Context: ngfv1alpha1.NginxContextHTTPServerLocation, Value: strings.Join(location, "\n") + "\n"})
	}
	return &ngfv1alpha1.SnippetsFilter{
		TypeMeta:   metav1.TypeMeta{APIVersion: ngfv1alpha1.SchemeGroupVersion.String(), Kind: "SnippetsFilter"},
		ObjectMeta: metav1.ObjectMeta{Name: naming.DNSLabel(routeName, "compat"), Namespace: ing.Namespace, Labels: labels},
		Spec:       ngfv1alpha1.SnippetsFilterSpec{Snippets: snippets},
	}, issues
}

func externalAuthSnippets(
	routeName, rawURL string,
	annotations map[string]string,
	authSnippet string,
	authProxyHeaders map[string]string,
	bodySize string,
) (string, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", fmt.Errorf("auth-url must be an absolute HTTP or HTTPS URL")
	}
	if u.User != nil || nginxUnsafePattern.MatchString(rawURL) || strings.Contains(rawURL, "$") {
		return "", "", fmt.Errorf("auth-url contains unsupported or unsafe characters")
	}
	internalName := "/_ngib_auth_" + strings.ReplaceAll(naming.DNSLabel(routeName), "-", "_")
	var server strings.Builder
	fmt.Fprintf(&server, "location = %s {\n", internalName)
	server.WriteString("  internal;\n  proxy_intercept_errors off;\n  proxy_pass_request_body off;\n")
	if bodySize != "" {
		fmt.Fprintf(&server, "  client_max_body_size %s;\n", bodySize)
	}
	server.WriteString("  proxy_set_header Content-Length \"\";\n  proxy_set_header X-Forwarded-Proto \"\";\n")
	server.WriteString("  proxy_set_header X-Request-ID $request_id;\n  proxy_set_header X-Original-URI $request_uri;\n")
	server.WriteString("  proxy_set_header X-Original-URL $scheme://$http_host$request_uri;\n")
	server.WriteString("  proxy_set_header X-Original-Method $request_method;\n")
	server.WriteString("  proxy_set_header X-Sent-From \"ingress-nginx-gateway-bridge\";\n")
	server.WriteString("  proxy_set_header X-Real-IP $remote_addr;\n  proxy_set_header X-Forwarded-For $remote_addr;\n")
	server.WriteString("  proxy_set_header X-Auth-Request-Redirect $request_uri;\n")
	headerNames := make([]string, 0, len(authProxyHeaders))
	for name := range authProxyHeaders {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	for _, name := range headerNames {
		value := authProxyHeaders[name]
		if !validHeaderName(name) || nginxUnsafePattern.MatchString(value) {
			return "", "", fmt.Errorf("auth-proxy-set-headers contains unsafe header %q", name)
		}
		if strings.TrimSpace(value) == "" {
			value = "\"\""
		}
		fmt.Fprintf(&server, "  proxy_set_header %s %s;\n", name, value)
	}
	fmt.Fprintf(&server, "  proxy_set_header Host %s;\n", u.Host)
	if u.Scheme == "https" {
		fmt.Fprintf(&server, "  proxy_ssl_server_name on;\n  proxy_ssl_name %s;\n", u.Hostname())
	}
	if authSnippet != "" {
		server.WriteString(authSnippet)
		server.WriteByte('\n')
	}
	fmt.Fprintf(&server, "  proxy_pass %s;\n}\n", u.String())

	var location strings.Builder
	fmt.Fprintf(&location, "auth_request %s;\n", internalName)
	location.WriteString("auth_request_set $ngib_auth_cookie $upstream_http_set_cookie;\n")
	location.WriteString("add_header Set-Cookie $ngib_auth_cookie;\n")
	for _, header := range splitCSV(annotations[annAuthResponseHeaders]) {
		if !validHeaderName(header) {
			return "", "", fmt.Errorf("auth-response-headers contains invalid header %q", header)
		}
		variable := nginxVariablePattern.ReplaceAllString(strings.ToLower(header), "_")
		fmt.Fprintf(&location, "auth_request_set $ngib_auth_%s $upstream_http_%s;\n", variable, variable)
		fmt.Fprintf(&location, "proxy_set_header %s $ngib_auth_%s;\n", header, variable)
	}
	if signin := strings.TrimSpace(annotations[annAuthSignin]); signin != "" {
		if nginxUnsafePattern.MatchString(signin) {
			return "", "", fmt.Errorf("auth-signin contains unsafe characters")
		}
		if strings.Contains(signin, "$escaped_request_uri") {
			return "", "", fmt.Errorf("auth-signin uses ingress-nginx-specific $escaped_request_uri, which NGINX Gateway Fabric does not define")
		}
		signinName := "@ngib_signin_" + strings.ReplaceAll(naming.DNSLabel(routeName), "-", "_")
		fmt.Fprintf(&location, "error_page 401 = %s;\n", signinName)
		fmt.Fprintf(&server, "location %s {\n  return 302 %s;\n}\n", signinName, signin)
	}
	return server.String(), location.String(), nil
}

func corsFilter(annotations map[string]string) (*gatewayv1.HTTPCORSFilter, []Issue) {
	if !parseBool(annotations[annEnableCORS]) {
		return nil, nil
	}
	filter := &gatewayv1.HTTPCORSFilter{
		AllowOrigins:     []gatewayv1.CORSOrigin{"*"},
		AllowMethods:     []gatewayv1.HTTPMethodWithWildcard{"GET", "PUT", "POST", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     toHeaderNames([]string{"DNT", "Keep-Alive", "User-Agent", "X-Requested-With", "If-Modified-Since", "Cache-Control", "Content-Type", "Range", "Authorization"}),
		AllowCredentials: ptr(true),
		MaxAge:           1728000,
	}
	if values := splitCSV(annotations[annCORSAllowOrigin]); len(values) > 0 {
		filter.AllowOrigins = make([]gatewayv1.CORSOrigin, 0, len(values))
		for _, value := range values {
			filter.AllowOrigins = append(filter.AllowOrigins, gatewayv1.CORSOrigin(value))
		}
	}
	if values := splitCSV(annotations[annCORSAllowMethods]); len(values) > 0 {
		filter.AllowMethods = make([]gatewayv1.HTTPMethodWithWildcard, 0, len(values))
		for _, value := range values {
			filter.AllowMethods = append(filter.AllowMethods, gatewayv1.HTTPMethodWithWildcard(value))
		}
	}
	var issues []Issue
	if values := splitCSV(annotations[annCORSAllowHeaders]); len(values) > 0 {
		for _, value := range values {
			if !validHeaderName(value) {
				issues = append(issues, Issue{Severity: SeverityError, Field: annCORSAllowHeaders, Message: fmt.Sprintf("invalid header %q", value)})
			}
		}
		filter.AllowHeaders = toHeaderNames(values)
	}
	if values := splitCSV(annotations[annCORSExposeHeaders]); len(values) > 0 {
		filter.ExposeHeaders = toHeaderNames(values)
	}
	if raw, ok := annotations[annCORSAllowCredentials]; ok {
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			issues = append(issues, Issue{Severity: SeverityError, Field: annCORSAllowCredentials, Message: "value must be true or false"})
		} else {
			filter.AllowCredentials = &value
		}
	}
	if raw := strings.TrimSpace(annotations[annCORSMaxAge]); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || value < 1 {
			issues = append(issues, Issue{Severity: SeverityError, Field: annCORSMaxAge, Message: "value must be a positive number of seconds"})
		} else {
			filter.MaxAge = int32(value)
		}
	}
	return filter, issues
}

func applicationParentRefs(
	namespace string,
	input hostInput,
	options GatewayOptions,
	attachHTTP bool,
) []gatewayv1.ParentReference {
	tls := input.tlsHostname != ""
	tlsOptions := options
	if input.tlsSectionName != "" {
		tlsOptions.HTTPSSectionName = input.tlsSectionName
	}
	refs := []gatewayv1.ParentReference{parentRef(namespace, tls, input.hostname, tlsOptions)}
	if attachHTTP {
		refs = append(refs, parentRef(namespace, false, input.hostname, options))
	}
	return refs
}

func parentRef(namespace string, tls bool, hostname string, options GatewayOptions) gatewayv1.ParentReference {
	ref := gatewayv1.ParentReference{Name: gatewayv1.ObjectName(options.Name)}
	if options.Namespace != "" && options.Namespace != namespace {
		ref.Namespace = ptr(gatewayv1.Namespace(options.Namespace))
	}
	section := options.HTTPSectionName
	if tls {
		section = options.HTTPSSectionName
	}
	if section != "" {
		ref.SectionName = ptr(gatewayv1.SectionName(section))
	}
	return ref
}

func buildRedirectRoute(ing *networkingv1.Ingress, hostname string, options Options) gatewayv1.HTTPRoute {
	name := naming.DNSLabel(ing.Name, hostNamePart(hostname), "redirect")
	scheme := "https"
	status := 308
	path := "/"
	pathType := gatewayv1.PathMatchPathPrefix
	return gatewayv1.HTTPRoute{
		TypeMeta:   metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "HTTPRoute"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ing.Namespace, Labels: sourceLabels(ing)},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{parentRef(ing.Namespace, false, hostname, options.Gateway)}},
			Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(hostname)},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
				Filters: []gatewayv1.HTTPRouteFilter{{
					Type:            gatewayv1.HTTPRouteFilterRequestRedirect,
					RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{Scheme: &scheme, StatusCode: &status},
				}},
			}},
		},
	}
}

func appendExtensionFilter(route *gatewayv1.HTTPRoute, kind, name string) {
	for idx := range route.Spec.Rules {
		appendExtensionFilterToRule(&route.Spec.Rules[idx], kind, name)
	}
}

func appendExtensionFilterToRule(rule *gatewayv1.HTTPRouteRule, kind, name string) {
	group := gatewayv1.Group(ngfv1alpha1.SchemeGroupVersion.Group)
	rule.Filters = append(rule.Filters, gatewayv1.HTTPRouteFilter{
		Type:         gatewayv1.HTTPRouteFilterExtensionRef,
		ExtensionRef: &gatewayv1.LocalObjectReference{Group: group, Kind: gatewayv1.Kind(kind), Name: gatewayv1.ObjectName(name)},
	})
}

func backendPort(ctx context.Context, namespace string, backend *networkingv1.IngressServiceBackend, resolvePort PortResolver) (int32, error) {
	if backend == nil {
		return 0, fmt.Errorf("resource backends are not supported")
	}
	if backend.Port.Number > 0 {
		return backend.Port.Number, nil
	}
	if backend.Port.Name == "" {
		return 0, fmt.Errorf("backend Service port is missing")
	}
	if resolvePort == nil {
		return 0, fmt.Errorf("backend uses named port %q but no resolver is configured", backend.Port.Name)
	}
	return resolvePort(ctx, namespace, backend.Name, backend.Port.Name)
}

func sourceLabels(ing *networkingv1.Ingress) map[string]string {
	return map[string]string{
		ManagedByLabel:       ControllerName,
		SourceNameLabel:      SourceNameLabelValue(ing.Name),
		SourceNamespaceLabel: ing.Namespace,
		SourceUIDLabel:       string(ing.UID),
	}
}

func sslRedirectEnabled(annotations map[string]string) bool {
	value, exists := annotations[annSSLRedirect]
	return !exists || parseBool(value)
}

func normalizeDuration(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !nginxDurationPattern.MatchString(value) {
		return "", fmt.Errorf("value %q is not supported by NGF ProxySettingsPolicy", value)
	}
	if _, err := strconv.Atoi(value); err == nil {
		return value + "s", nil
	}
	return value, nil
}

func parseNginxBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "yes", "1":
		return true, nil
	case "off", "false", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("value must be on/off or true/false")
	}
}

func parseBool(value string) bool {
	parsed, _ := parseNginxBool(value)
	return parsed
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func toHeaderNames(values []string) []gatewayv1.HTTPHeaderName {
	result := make([]gatewayv1.HTTPHeaderName, 0, len(values))
	for _, value := range values {
		result = append(result, gatewayv1.HTTPHeaderName(value))
	}
	return result
}

func validHeaderName(value string) bool {
	return http.CanonicalHeaderKey(value) != "" && !strings.ContainsAny(value, " \t\r\n:")
}

func validateGeneratedRewrite(path, target string) error {
	if nginxUnsafePattern.MatchString(path) || strings.ContainsAny(path, " \t") {
		return fmt.Errorf("regex path contains characters unsafe for generated NGINX configuration")
	}
	if nginxUnsafePattern.MatchString(target) || strings.ContainsAny(target, " \t") || !strings.HasPrefix(target, "/") {
		return fmt.Errorf("capture-group rewrite target contains unsafe characters or is not an absolute path")
	}
	return nil
}

func hostNamePart(host string) string {
	if host == "" {
		return "default"
	}
	return host
}

func matchingTLSHost(host string, tlsHosts map[string]struct{}) string {
	if host == "" {
		return ""
	}
	if _, exact := tlsHosts[host]; exact {
		return host
	}
	best := ""
	for candidate := range tlsHosts {
		if !strings.HasPrefix(candidate, "*.") {
			continue
		}
		suffix := strings.TrimPrefix(candidate, "*")
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) && len(candidate) > len(best) {
			best = candidate
		}
	}
	return best
}

func ptr[T any](value T) *T { return &value }
