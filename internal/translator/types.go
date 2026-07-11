// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	ngfv1alpha1 "github.com/nginx/nginx-gateway-fabric/v2/apis/v1alpha1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/naming"
)

const (
	ManagedByLabel         = "gateway.zyno.io/managed-by"
	SourceNameLabel        = "gateway.zyno.io/source-name"
	SourceNamespaceLabel   = "gateway.zyno.io/source-namespace"
	SourceUIDLabel         = "gateway.zyno.io/source-uid"
	GatewayLabel           = "gateway.zyno.io/gateway"
	TranslationStatusLabel = "gateway.zyno.io/translation-status"
	ControllerName         = "ingress-nginx-gateway-bridge"
	EnabledAnnotation      = "gateway.zyno.io/enabled"
	IgnoreAnnotation       = "gateway.zyno.io/ignore"
)

const (
	TranslationStatusReady   = "ready"
	TranslationStatusPending = "pending"
	TranslationStatusFailed  = "failed"
)

// SourceNameLabelValue returns a valid label value for an Ingress name.
func SourceNameLabelValue(name string) string {
	if len(name) <= 63 {
		return name
	}
	return naming.DNSLabel(name)
}

// GatewayLabelValue identifies one managed Gateway without exceeding label limits.
func GatewayLabelValue(namespace, name string) string {
	return naming.DNSLabel(namespace, name)
}

type Severity string

const (
	SeverityError   Severity = "Error"
	SeverityWarning Severity = "Warning"
)

// Issue describes a compatibility decision made while translating an Ingress.
type Issue struct {
	Severity Severity
	Field    string
	Message  string
}

// Fatal reports whether any issue prevents faithful activation of the generated route.
func (i Issue) Fatal() bool { return i.Severity == SeverityError }

// GatewayOptions identifies the parent Gateway and listener ownership mode.
type GatewayOptions struct {
	Namespace        string
	Name             string
	HTTPSectionName  string
	HTTPSSectionName string
	TLSSections      map[string]string
	ManagedListeners bool
}

// Options controls compatibility behavior.
type Options struct {
	Gateway GatewayOptions
	// TLSHosts is the cluster-wide set of hostnames covered by the managed
	// Gateway listener. When nil, translation falls back to the source
	// Ingress's own TLS declarations for route-only installations.
	TLSHosts           map[string]struct{}
	AllowSnippets      bool
	Strict             bool
	SettingsAsSnippets bool
}

// Plan contains all namespaced objects derived from one Ingress.
type Plan struct {
	HTTPRoutes             []gatewayv1.HTTPRoute
	BackendTLSPolicies     []gatewayv1.BackendTLSPolicy
	ClientSettingsPolicies []ngfv1alpha1.ClientSettingsPolicy
	ProxySettingsPolicies  []ngfv1alpha1.ProxySettingsPolicy
	AuthenticationFilters  []ngfv1alpha1.AuthenticationFilter
	SnippetsFilters        []ngfv1alpha1.SnippetsFilter
	Issues                 []Issue
}

// Fatal reports whether the plan must not be activated.
func (p Plan) Fatal() bool {
	for _, issue := range p.Issues {
		if issue.Fatal() {
			return true
		}
	}
	return false
}
