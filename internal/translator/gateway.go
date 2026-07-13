// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	"fmt"
	"sort"
	"strings"

	ngfv1alpha2 "github.com/nginx/nginx-gateway-fabric/v2/apis/v1alpha2"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/naming"
)

// ManagedGatewayOptions controls the shared Gateway generated in hot-swap mode.
type ManagedGatewayOptions struct {
	Namespace         string
	Name              string
	ClassName         string
	NginxProxyName    string
	AllowListenerSets bool
	HTTPSectionName   string
	HTTPSSectionName  string
}

// GatewayPlan is the cluster-wide listener projection of all selected Ingresses.
type GatewayPlan struct {
	Gateway         gatewayv1.Gateway
	ReferenceGrants []gatewayv1.ReferenceGrant
	TLSHosts        map[string]struct{}
	TLSSections     map[string]string
	Issues          map[types.NamespacedName][]Issue
}

type certificateSource struct {
	namespace string
	secret    string
	source    types.NamespacedName
}

// BuildManagedGateway creates one HTTP listener and one HTTPS listener per unique TLS hostname.
func BuildManagedGateway(ingresses []networkingv1.Ingress, options ManagedGatewayOptions) GatewayPlan {
	fromAll := gatewayv1.NamespacesFromAll
	allowedRoutes := &gatewayv1.AllowedRoutes{Namespaces: &gatewayv1.RouteNamespaces{From: &fromAll}}
	plan := GatewayPlan{
		TLSHosts:    make(map[string]struct{}),
		TLSSections: make(map[string]string),
		Issues:      make(map[types.NamespacedName][]Issue),
	}
	plan.Gateway = gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "Gateway"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      options.Name,
			Namespace: options.Namespace,
			Labels: map[string]string{
				ManagedByLabel: ControllerName,
				GatewayLabel:   GatewayLabelValue(options.Namespace, options.Name),
			},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(options.ClassName),
			Listeners: []gatewayv1.Listener{{
				Name:          gatewayv1.SectionName(options.HTTPSectionName),
				Port:          80,
				Protocol:      gatewayv1.HTTPProtocolType,
				AllowedRoutes: allowedRoutes,
			}},
		},
	}
	if options.NginxProxyName != "" {
		plan.Gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{
				Group: gatewayv1.Group(ngfv1alpha2.GroupName),
				Kind:  "NginxProxy",
				Name:  options.NginxProxyName,
			},
		}
	}
	if options.AllowListenerSets {
		fromSame := gatewayv1.NamespacesFromSame
		plan.Gateway.Spec.AllowedListeners = &gatewayv1.AllowedListeners{
			Namespaces: &gatewayv1.ListenerNamespaces{From: &fromSame},
		}
	}

	certificates := make(map[string]certificateSource)
	tlsSources := make(map[types.NamespacedName]struct{})
	grantKeys := make(map[string]struct{})
	for idx := range ingresses {
		ing := &ingresses[idx]
		if !ing.DeletionTimestamp.IsZero() {
			continue
		}
		source := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		for _, tls := range ing.Spec.TLS {
			tlsSources[source] = struct{}{}
			secret := strings.TrimSpace(tls.SecretName)
			if secret == "" {
				plan.Issues[source] = append(plan.Issues[source], Issue{
					Severity: SeverityError,
					Field:    "spec.tls.secretName",
					Message:  "managed listeners require a TLS Secret name",
				})
				continue
			}
			hosts := effectiveTLSHosts(ing, tls)
			if len(hosts) == 0 {
				plan.Issues[source] = append(plan.Issues[source], Issue{
					Severity: SeverityError,
					Field:    "spec.tls.hosts",
					Message:  "TLS entry has no hosts and the Ingress has no named rules from which to infer them",
				})
				continue
			}
			for _, rawHost := range hosts {
				host := strings.ToLower(strings.TrimSpace(rawHost))
				if host == "" {
					plan.Issues[source] = append(plan.Issues[source], Issue{
						Severity: SeverityError,
						Field:    "spec.tls.hosts",
						Message:  "managed listeners do not support an empty TLS hostname",
					})
					continue
				}
				candidate := certificateSource{namespace: ing.Namespace, secret: secret, source: source}
				if existing, exists := certificates[host]; exists &&
					(existing.namespace != candidate.namespace || existing.secret != candidate.secret) {
					message := fmt.Sprintf(
						"TLS hostname %q conflicts with Secret %s/%s selected by Ingress %s/%s",
						host, existing.namespace, existing.secret, existing.source.Namespace, existing.source.Name,
					)
					plan.Issues[source] = append(plan.Issues[source], Issue{Severity: SeverityError, Field: "spec.tls", Message: message})
					plan.Issues[existing.source] = append(plan.Issues[existing.source], Issue{Severity: SeverityError, Field: "spec.tls", Message: message})
					continue
				}
				plan.TLSHosts[host] = struct{}{}
				certificates[host] = candidate
			}
			if ing.Namespace != options.Namespace {
				key := ing.Namespace + "/" + secret
				if _, exists := grantKeys[key]; !exists {
					grantKeys[key] = struct{}{}
					plan.ReferenceGrants = append(plan.ReferenceGrants, certificateReferenceGrant(ing, options, secret))
				}
			}
		}
	}

	// Gateway API permits at most 64 listeners. Reserve one for HTTP.
	if len(certificates) > 63 {
		for source := range tlsSources {
			plan.Issues[source] = append(plan.Issues[source], Issue{
				Severity: SeverityError,
				Field:    "spec.tls",
				Message:  "the managed Gateway cannot contain more than 63 TLS hostnames alongside its HTTP listener",
			})
		}
		return plan
	}

	hosts := make([]string, 0, len(certificates))
	for host := range certificates {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	mode := gatewayv1.TLSModeTerminate
	for _, host := range hosts {
		certificate := certificates[host]
		secretNamespace := gatewayv1.Namespace(certificate.namespace)
		sectionName := naming.DNSLabel(options.HTTPSSectionName, host)
		plan.TLSSections[host] = sectionName
		listenerHostname := gatewayv1.Hostname(host)
		plan.Gateway.Spec.Listeners = append(plan.Gateway.Spec.Listeners, gatewayv1.Listener{
			Name:     gatewayv1.SectionName(sectionName),
			Hostname: &listenerHostname,
			Port:     443,
			Protocol: gatewayv1.HTTPSProtocolType,
			TLS: &gatewayv1.ListenerTLSConfig{
				Mode: &mode,
				CertificateRefs: []gatewayv1.SecretObjectReference{{
					Name: gatewayv1.ObjectName(certificate.secret), Namespace: &secretNamespace,
				}},
			},
			AllowedRoutes: allowedRoutes,
		})
	}
	return plan
}

// effectiveTLSHosts reproduces ingress-nginx's behavior for a TLS entry with
// an omitted hosts list by applying that entry to every named rule on the same
// Ingress. Hostless/default-backend TLS cannot be projected safely onto the
// shared hostname listener.
func effectiveTLSHosts(ing *networkingv1.Ingress, tls networkingv1.IngressTLS) []string {
	if len(tls.Hosts) > 0 {
		result := make([]string, 0, len(tls.Hosts))
		for _, raw := range tls.Hosts {
			if host := strings.ToLower(strings.TrimSpace(raw)); host != "" {
				result = append(result, host)
			}
		}
		return result
	}

	seen := make(map[string]struct{})
	result := make([]string, 0, len(ing.Spec.Rules))
	for _, rule := range ing.Spec.Rules {
		host := strings.ToLower(strings.TrimSpace(rule.Host))
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		result = append(result, host)
	}
	return result
}

func certificateReferenceGrant(
	ing *networkingv1.Ingress,
	options ManagedGatewayOptions,
	secret string,
) gatewayv1.ReferenceGrant {
	return gatewayv1.ReferenceGrant{
		TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "ReferenceGrant"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      naming.DNSLabel(options.Name, secret, "gateway-cert"),
			Namespace: ing.Namespace,
			Labels: map[string]string{
				ManagedByLabel: ControllerName,
				GatewayLabel:   GatewayLabelValue(options.Namespace, options.Name),
			},
		},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: []gatewayv1.ReferenceGrantFrom{{
				Group:     gatewayv1.Group(gatewayv1.GroupVersion.Group),
				Kind:      "Gateway",
				Namespace: gatewayv1.Namespace(options.Namespace),
			}},
			To: []gatewayv1.ReferenceGrantTo{{
				Group: "",
				Kind:  "Secret",
				Name:  ptr(gatewayv1.ObjectName(secret)),
			}},
		},
	}
}
