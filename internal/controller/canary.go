// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"sort"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
)

const ingressNginxCanaryAnnotation = "nginx.ingress.kubernetes.io/canary"

func isCanaryIngress(ing *networkingv1.Ingress) bool {
	return annotationBool(ing.Annotations[ingressNginxCanaryAnnotation])
}

// canaryAssignments maps each canary Ingress to the oldest primary Ingress
// that contains every hostname/path footprint declared by the canary. This
// matches ingress-nginx's oldest-rule precedence when more than one primary
// Ingress could correspond to a canary.
func canaryAssignments(ingresses []networkingv1.Ingress) map[string]string {
	primaries := make([]*networkingv1.Ingress, 0, len(ingresses))
	for idx := range ingresses {
		if !isCanaryIngress(&ingresses[idx]) {
			primaries = append(primaries, &ingresses[idx])
		}
	}

	result := make(map[string]string)
	for idx := range ingresses {
		canary := &ingresses[idx]
		if !isCanaryIngress(canary) {
			continue
		}
		canaryFootprints := ingressSpecRouteFootprints(canary)
		if len(canaryFootprints) == 0 {
			continue
		}
		candidates := make([]*networkingv1.Ingress, 0, 1)
		for _, primary := range primaries {
			if footprintsContain(ingressSpecRouteFootprints(primary), canaryFootprints) {
				candidates = append(candidates, primary)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		sort.Slice(candidates, func(i, j int) bool {
			left, right := candidates[i], candidates[j]
			if left.CreationTimestamp.Equal(&right.CreationTimestamp) {
				return left.Name < right.Name
			}
			return left.CreationTimestamp.Time.Before(right.CreationTimestamp.Time)
		})
		result[canary.Name] = candidates[0].Name
	}
	return result
}

func ingressSpecRouteFootprints(ingress *networkingv1.Ingress) map[string]struct{} {
	result := make(map[string]struct{})
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(rule.Host))
		for _, path := range rule.HTTP.Paths {
			value := path.Path
			if value == "" {
				value = "/"
			}
			result[host+"\x00"+value] = struct{}{}
		}
	}
	if ingress.Spec.DefaultBackend != nil {
		result["\x00/"] = struct{}{}
	}
	return result
}

func footprintsContain(primary, canary map[string]struct{}) bool {
	for footprint := range canary {
		if _, exists := primary[footprint]; !exists {
			return false
		}
	}
	return true
}
