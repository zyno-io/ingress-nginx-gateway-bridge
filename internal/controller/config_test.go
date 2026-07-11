// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

func TestConfigSelected(t *testing.T) {
	nginx := "nginx"
	other := "other"
	config := Config{
		WatchIngressWithoutClass: true,
		IngressClasses:           map[string]struct{}{"nginx": {}},
	}
	tests := []struct {
		name        string
		class       *string
		annotations map[string]string
		want        bool
	}{
		{name: "classless hot swap", want: true},
		{name: "configured class", class: &nginx, want: true},
		{name: "other class", class: &other, want: false},
		{name: "explicit opt in", class: &other, annotations: map[string]string{translator.EnabledAnnotation: "true"}, want: true},
		{name: "explicit opt out", annotations: map[string]string{translator.IgnoreAnnotation: "true"}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Annotations: test.annotations}}
			ing.Spec.IngressClassName = test.class
			if got := config.Selected(ing); got != test.want {
				t.Fatalf("Selected() = %v, want %v", got, test.want)
			}
		})
	}
}
