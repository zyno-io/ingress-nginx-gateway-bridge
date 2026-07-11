// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"strings"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

// Config controls the controller's source selection and target Gateway.
type Config struct {
	GatewayNamespace string
	GatewayName      string
	GatewayClassName string
	NginxProxyName   string
	ManageGateway    bool
	HTTPSectionName  string
	HTTPSSectionName string

	WatchIngressWithoutClass bool
	IngressClasses           map[string]struct{}
	AllowSnippets            bool
	Strict                   bool
	UpdateIngressStatus      bool
}

// Selected reports whether the Ingress belongs to this bridge.
func (c Config) Selected(ing *networkingv1.Ingress) bool {
	if value, ok := ing.Annotations[translator.IgnoreAnnotation]; ok && annotationBool(value) {
		return false
	}
	if value, ok := ing.Annotations[translator.EnabledAnnotation]; ok {
		return annotationBool(value)
	}

	class := ""
	if ing.Spec.IngressClassName != nil {
		class = *ing.Spec.IngressClassName
	} else {
		class = ing.Annotations["kubernetes.io/ingress.class"]
	}
	class = strings.TrimSpace(class)
	if class == "" {
		return c.WatchIngressWithoutClass
	}
	_, selected := c.IngressClasses[class]
	return selected
}

func annotationBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "on", "true", "yes":
		return true
	default:
		return false
	}
}
