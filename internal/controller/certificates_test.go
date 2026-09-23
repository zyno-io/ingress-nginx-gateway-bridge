// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func generateControllerTestCertificate(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// transformedSecret builds a raw TLS Secret and runs it through
// transformTLSSecret, matching what the cache would hand event handlers.
func transformedSecret(t *testing.T, namespace, name string, cert, key []byte) *corev1.Secret {
	t.Helper()
	raw := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": cert, "tls.key": key},
	}
	out, err := transformTLSSecret(raw)
	if err != nil {
		t.Fatalf("transformTLSSecret: %v", err)
	}
	secret, ok := out.(*corev1.Secret)
	if !ok {
		t.Fatalf("transformTLSSecret returned %T, want *corev1.Secret", out)
	}
	return secret
}

func TestTransformTLSSecretStripsSensitiveFields(t *testing.T) {
	cert, key := generateControllerTestCertificate(t, "*.example.com")
	raw := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tls", Namespace: "apps",
			Annotations: map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{}"},
			Labels:      map[string]string{"app": "demo"},
			ManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: "kubectl", Operation: metav1.ManagedFieldsOperationUpdate,
			}},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": cert, "tls.key": key},
	}
	out, err := transformTLSSecret(raw)
	if err != nil {
		t.Fatalf("transformTLSSecret: %v", err)
	}
	secret := out.(*corev1.Secret)
	if secret.Data != nil {
		t.Fatalf("Data was not stripped: %#v", secret.Data)
	}
	if len(secret.Labels) != 0 {
		t.Fatalf("Labels was not stripped: %#v", secret.Labels)
	}
	if len(secret.ManagedFields) != 0 {
		t.Fatalf("ManagedFields was not stripped: %#v", secret.ManagedFields)
	}
	if _, hasLastApplied := secret.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; hasLastApplied {
		t.Fatal("last-applied-configuration annotation was not stripped")
	}
	raw2, ok := secret.Annotations[certificateInfoAnnotation]
	if !ok || raw2 == "" {
		t.Fatalf("expected a non-empty certificate-info annotation, got %q", raw2)
	}
	if info, ok := certificateInfoFromSecret(secret); !ok || len(info.WildcardSANs) != 1 || info.WildcardSANs[0] != "*.example.com" {
		t.Fatalf("decoded certificate info = %#v, ok=%v", info, ok)
	}
}

func TestTransformTLSSecretIdempotent(t *testing.T) {
	cert, key := generateControllerTestCertificate(t, "*.example.com")
	first := transformedSecret(t, "apps", "tls", cert, key)
	out, err := transformTLSSecret(first)
	if err != nil {
		t.Fatalf("transformTLSSecret: %v", err)
	}
	second := out.(*corev1.Secret)
	if second.Annotations[certificateInfoAnnotation] != first.Annotations[certificateInfoAnnotation] {
		t.Fatalf("re-transforming an already-transformed Secret changed its annotation: %q vs %q",
			first.Annotations[certificateInfoAnnotation], second.Annotations[certificateInfoAnnotation])
	}
}

func TestTransformTLSSecretBadKeyProducesEmptyAnnotation(t *testing.T) {
	cert, _ := generateControllerTestCertificate(t, "a.example.com")
	_, otherKey := generateControllerTestCertificate(t, "a.example.com")
	raw := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "apps"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": cert, "tls.key": otherKey},
	}
	out, err := transformTLSSecret(raw)
	if err != nil {
		t.Fatalf("transformTLSSecret must never return an error: %v", err)
	}
	secret := out.(*corev1.Secret)
	if got := secret.Annotations[certificateInfoAnnotation]; got != "" {
		t.Fatalf("certificate-info annotation = %q, want empty for an invalid key pair", got)
	}
	if _, ok := certificateInfoFromSecret(secret); ok {
		t.Fatal("certificateInfoFromSecret must report false for an empty annotation")
	}
}

func TestSecretEventHandlerOnPlainWorkqueue(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		func(s *runtime.Scheme) error { corev1.AddToScheme(s); return nil },
		networkingv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	certA, keyA := generateControllerTestCertificate(t, "*.example.com")
	certB, keyB := generateControllerTestCertificate(t, "*.example.com") // renewal: same SAN, new chain
	certC, keyC := generateControllerTestCertificate(t, "*.other.example.com")

	oldSecret := transformedSecret(t, "apps", "tls-secret", certA, keyA)
	renewalSecret := transformedSecret(t, "apps", "tls-secret", certB, keyB)
	sanChangeSecret := transformedSecret(t, "apps", "tls-secret", certC, keyC)

	ing := managedTestIngress("apps", "app", "tls-secret", "a.example.com")
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ing).Build()
	reconciler := &IngressReconciler{Client: fakeClient, Config: Config{WatchIngressWithoutClass: true}}
	handler := reconciler.secretEventHandler()

	newQueue := func() workqueue.TypedRateLimitingInterface[reconcile.Request] {
		return workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	}

	t.Run("renewal-like update delays instead of enqueueing immediately", func(t *testing.T) {
		q := newQueue()
		handler.Update(context.Background(), event.UpdateEvent{ObjectOld: oldSecret, ObjectNew: renewalSecret}, q)
		if got := q.Len(); got != 0 {
			t.Fatalf("queue length = %d, want 0 immediately after a renewal-shaped update", got)
		}
	})

	t.Run("SAN change enqueues immediately", func(t *testing.T) {
		q := newQueue()
		handler.Update(context.Background(), event.UpdateEvent{ObjectOld: oldSecret, ObjectNew: sanChangeSecret}, q)
		if got := q.Len(); got != 1 {
			t.Fatalf("queue length = %d, want 1 immediately after a wildcard SAN change", got)
		}
	})

	t.Run("unreferenced Secret is ignored", func(t *testing.T) {
		other := transformedSecret(t, "apps", "unused-secret", certA, keyA)
		q := newQueue()
		handler.Create(context.Background(), event.CreateEvent{Object: other}, q)
		if got := q.Len(); got != 0 {
			t.Fatalf("queue length = %d, want 0 for a Secret no selected Ingress references", got)
		}
	})
}

// TestCertificateInfosPrunesUnreferencedSecrets guards against a Secret's
// cached certificate info surviving a period where no Ingress referenced it.
// The event handler intentionally does not enqueue a sync for an unreferenced
// Secret's changes, so certificateInfos itself must drop the stale entry as
// soon as nothing selects it, or a later re-reference would read stale data.
func TestCertificateInfosPrunesUnreferencedSecrets(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		func(s *runtime.Scheme) error { return corev1.AddToScheme(s) },
		networkingv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	certA, keyA := generateControllerTestCertificate(t, "*.a.example.com")
	certB, keyB := generateControllerTestCertificate(t, "*.b.example.com")
	secret := transformedSecret(t, "apps", "shared", certA, keyA)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	reconciler := &IngressReconciler{
		Client: fakeClient,
		Config: Config{WatchIngressWithoutClass: true, CollapseWildcardCertificates: true},
	}
	ing := managedTestIngress("apps", "app", "shared", "a.example.com")
	key := types.NamespacedName{Namespace: "apps", Name: "shared"}
	ctx := context.Background()

	first, err := reconciler.certificateInfos(ctx, []networkingv1.Ingress{*ing})
	if err != nil {
		t.Fatalf("certificateInfos: %v", err)
	}
	if info, ok := first[key]; !ok || info.WildcardSANs[0] != "*.a.example.com" {
		t.Fatalf("first read = %#v, ok=%v", info, ok)
	}
	if _, cached := reconciler.certificates[key]; !cached {
		t.Fatal("expected the Secret to be cached")
	}

	// No Ingress selects the Secret this round: it must be pruned, not just skipped.
	if _, err := reconciler.certificateInfos(ctx, nil); err != nil {
		t.Fatalf("certificateInfos: %v", err)
	}
	if _, cached := reconciler.certificates[key]; cached {
		t.Fatal("expected the cache entry to be pruned once nothing references it")
	}

	// The Secret is reissued while unreferenced (the event handler correctly
	// ignores this), then the Ingress reappears.
	var current corev1.Secret
	if err := reconciler.Get(ctx, key, &current); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	updated := transformedSecret(t, "apps", "shared", certB, keyB)
	updated.ResourceVersion = current.ResourceVersion
	if err := reconciler.Update(ctx, updated); err != nil {
		t.Fatalf("update secret: %v", err)
	}

	second, err := reconciler.certificateInfos(ctx, []networkingv1.Ingress{*ing})
	if err != nil {
		t.Fatalf("certificateInfos: %v", err)
	}
	if info, ok := second[key]; !ok || info.WildcardSANs[0] != "*.b.example.com" {
		t.Fatalf("re-referenced Secret served stale info: %#v, ok=%v", info, ok)
	}
}
