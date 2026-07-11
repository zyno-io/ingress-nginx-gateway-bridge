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
	Namespace        string
	Name             string
	ClassName        string
	NginxProxyName   string
	HTTPSectionName  string
	HTTPSSectionName string
}

// GatewayPlan is the cluster-wide listener projection of all selected Ingresses.
type GatewayPlan struct {
	Gateway         gatewayv1.Gateway
	ReferenceGrants []gatewayv1.ReferenceGrant
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
	plan := GatewayPlan{Issues: make(map[types.NamespacedName][]Issue)}
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

	certificates := make(map[string]certificateSource)
	certificateRefs := make(map[string]certificateSource)
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
			for _, rawHost := range tls.Hosts {
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
				certificates[host] = candidate
			}
			certificateRefs[ing.Namespace+"/"+secret] = certificateSource{
				namespace: ing.Namespace, secret: secret, source: source,
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

	if len(certificateRefs) > 64 {
		for source := range tlsSources {
			plan.Issues[source] = append(plan.Issues[source], Issue{
				Severity: SeverityError,
				Field:    "spec.tls",
				Message:  "the shared HTTPS listener cannot reference more than 64 distinct TLS Secrets",
			})
		}
		return plan
	}

	if len(certificateRefs) > 0 {
		keys := make([]string, 0, len(certificateRefs))
		for key := range certificateRefs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		refs := make([]gatewayv1.SecretObjectReference, 0, len(keys))
		for _, key := range keys {
			certificate := certificateRefs[key]
			secretNamespace := gatewayv1.Namespace(certificate.namespace)
			refs = append(refs, gatewayv1.SecretObjectReference{
				Name: gatewayv1.ObjectName(certificate.secret), Namespace: &secretNamespace,
			})
		}
		mode := gatewayv1.TLSModeTerminate
		plan.Gateway.Spec.Listeners = append(plan.Gateway.Spec.Listeners, gatewayv1.Listener{
			Name:     gatewayv1.SectionName(options.HTTPSSectionName),
			Port:     443,
			Protocol: gatewayv1.HTTPSProtocolType,
			TLS: &gatewayv1.ListenerTLSConfig{
				Mode: &mode, CertificateRefs: refs,
			},
			AllowedRoutes: allowedRoutes,
		})
	}
	return plan
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
