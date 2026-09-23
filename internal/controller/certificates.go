// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

const (
	// certificateInfoAnnotation carries a Secret's cache-only CertificateInfo
	// projection. It exists solely inside the controller's informer cache and
	// is never read from or written to the API server.
	certificateInfoAnnotation = "gateway.zyno.io/internal-certificate-info"
	// certificateSettleDelay defers reacting to a renewal-shaped Secret
	// update (same wildcard SANs, new fingerprint) so a multi-step cert-manager
	// rollout settles before the managed Gateway repoints listeners.
	certificateSettleDelay = 10 * time.Second
)

// certificateSyncKey is the dedicated reconcile request used to react to TLS
// Secret changes without reconciling a specific Ingress.
var certificateSyncKey = types.NamespacedName{Name: "ingress-nginx-gateway-bridge-certificate-sync"}

// certificateEntry caches one Secret's certificate lookup, including
// negative results, so a missing or invalid Secret is not re-fetched on
// every plan.
type certificateEntry struct {
	info translator.CertificateInfo
	ok   bool
}

// SecretCacheByObject restricts the informer cache to `kubernetes.io/tls`
// Secrets and strips them down to a CertificateInfo projection before they
// are committed to the cache, so no certificate or key material is retained.
func SecretCacheByObject() cache.ByObject {
	return cache.ByObject{
		Field:     fields.OneTermEqualSelector("type", string(corev1.SecretTypeTLS)),
		Transform: transformTLSSecret,
	}
}

// transformTLSSecret replaces a Secret's data and metadata with only what
// the controller needs to plan wildcard collapse: a JSON-encoded
// CertificateInfo annotation (or an empty one, if the Secret is not a valid
// certificate) and the identity/type fields required to route events. It
// never returns an error, since a Secret that fails to parse is still a
// valid, if uncollapsible, cache entry.
func transformTLSSecret(obj interface{}) (interface{}, error) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return obj, nil
	}
	if secret.Data == nil {
		if _, present := secret.Annotations[certificateInfoAnnotation]; present {
			// Already transformed; avoid recomputing on every resync.
			return secret, nil
		}
	}

	encoded := ""
	if info, ok := translator.ParseCertificateInfo(secret.Data); ok {
		if data, err := json.Marshal(info); err == nil {
			encoded = string(data)
		}
	}

	return &corev1.Secret{
		TypeMeta: secret.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:              secret.Name,
			Namespace:         secret.Namespace,
			UID:               secret.UID,
			ResourceVersion:   secret.ResourceVersion,
			Generation:        secret.Generation,
			CreationTimestamp: secret.CreationTimestamp,
			DeletionTimestamp: secret.DeletionTimestamp,
			Annotations:       map[string]string{certificateInfoAnnotation: encoded},
		},
		Type: secret.Type,
	}, nil
}

// certificateInfoFromSecret decodes the CertificateInfo a cache Transform
// previously attached to a Secret. It reports false for a Secret with no
// annotation (untransformed) or an empty one (transformed, but invalid).
func certificateInfoFromSecret(obj client.Object) (translator.CertificateInfo, bool) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return translator.CertificateInfo{}, false
	}
	raw, present := secret.Annotations[certificateInfoAnnotation]
	if !present || raw == "" {
		return translator.CertificateInfo{}, false
	}
	var info translator.CertificateInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return translator.CertificateInfo{}, false
	}
	return info, true
}

// certificateInfos resolves the CertificateInfo for every TLS Secret
// referenced by selected. It must be called with managedMu held: it lazily
// initializes and updates r.certificates, the sticky per-Secret snapshot
// used across reconciliations. It returns nil when wildcard collapse is
// disabled, and otherwise a map containing only successfully parsed
// certificates (a referenced but invalid or missing Secret is simply absent).
func (r *IngressReconciler) certificateInfos(
	ctx context.Context,
	selected []networkingv1.Ingress,
) (map[types.NamespacedName]translator.CertificateInfo, error) {
	if !r.Config.CollapseWildcardCertificates {
		return nil, nil
	}
	if r.certificates == nil {
		r.certificates = make(map[types.NamespacedName]certificateEntry)
	}

	referenced := make(map[types.NamespacedName]struct{})
	result := make(map[types.NamespacedName]translator.CertificateInfo)
	for idx := range selected {
		ing := &selected[idx]
		for _, tls := range ing.Spec.TLS {
			name := strings.TrimSpace(tls.SecretName)
			if name == "" {
				continue
			}
			key := types.NamespacedName{Namespace: ing.Namespace, Name: name}
			referenced[key] = struct{}{}
			entry, cached := r.certificates[key]
			if !cached {
				var err error
				entry, err = r.readCertificate(ctx, key)
				if err != nil {
					return nil, err
				}
				r.certificates[key] = entry
			}
			if entry.ok {
				result[key] = entry.info
			}
		}
	}
	// Drop cache entries for Secrets no longer referenced by any selected
	// Ingress. Otherwise a Secret that changes while briefly unreferenced
	// (the event handler intentionally ignores unreferenced Secrets) would
	// serve stale certificate info forever once it becomes referenced again.
	for key := range r.certificates {
		if _, keep := referenced[key]; !keep {
			delete(r.certificates, key)
		}
	}
	return result, nil
}

// readCertificate fetches one TLS Secret's cached CertificateInfo. A missing
// Secret is a negative cache entry, not an error, since an Ingress may
// reference a Secret that has not been created yet.
func (r *IngressReconciler) readCertificate(ctx context.Context, key types.NamespacedName) (certificateEntry, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return certificateEntry{}, nil
		}
		return certificateEntry{}, err
	}
	info, ok := certificateInfoFromSecret(&secret)
	return certificateEntry{info: info, ok: ok}, nil
}

// secretEventHandler enqueues the dedicated certificate-sync request when a
// referenced TLS Secret changes. It never enqueues an Ingress reconciliation
// directly; affected Ingresses are pushed separately once the new plan is known.
func (r *IngressReconciler) secretEventHandler() handler.EventHandler {
	return handler.Funcs{
		CreateFunc: func(ctx context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			r.enqueueCertificateSync(ctx, e.Object, q, 0)
		},
		DeleteFunc: func(ctx context.Context, e event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			r.enqueueCertificateSync(ctx, e.Object, q, 0)
		},
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			oldInfo, oldOK := certificateInfoFromSecret(e.ObjectOld)
			newInfo, newOK := certificateInfoFromSecret(e.ObjectNew)
			if oldOK == newOK && oldInfo.Fingerprint == newInfo.Fingerprint && slices.Equal(oldInfo.WildcardSANs, newInfo.WildcardSANs) {
				return
			}
			delay := time.Duration(0)
			if oldOK && newOK && slices.Equal(oldInfo.WildcardSANs, newInfo.WildcardSANs) && oldInfo.Fingerprint != newInfo.Fingerprint {
				// Same wildcard coverage, new chain: a renewal-shaped update.
				// Delay briefly so a multi-step rollout settles before replanning.
				delay = certificateSettleDelay
			}
			r.enqueueCertificateSync(ctx, e.ObjectNew, q, delay)
		},
	}
}

// enqueueCertificateSync queues the certificate-sync request, but only when
// some selected Ingress actually references the changed Secret.
func (r *IngressReconciler) enqueueCertificateSync(
	ctx context.Context,
	secret client.Object,
	q workqueue.TypedRateLimitingInterface[reconcile.Request],
	delay time.Duration,
) {
	if !r.secretReferenced(ctx, secret.GetNamespace(), secret.GetName()) {
		return
	}
	request := reconcile.Request{NamespacedName: certificateSyncKey}
	if delay > 0 {
		q.AddAfter(request, delay)
		return
	}
	q.Add(request)
}

// secretReferenced reports whether a selected, non-deleting Ingress in
// namespace names secret in its TLS block. A List failure fails open so a
// transient cache error cannot silently drop a certificate change.
func (r *IngressReconciler) secretReferenced(ctx context.Context, namespace, name string) bool {
	var ingresses networkingv1.IngressList
	if err := r.List(ctx, &ingresses, client.InNamespace(namespace)); err != nil {
		return true
	}
	for idx := range ingresses.Items {
		ing := &ingresses.Items[idx]
		if !ing.DeletionTimestamp.IsZero() || !r.Config.Selected(ing) {
			continue
		}
		for _, tls := range ing.Spec.TLS {
			if strings.TrimSpace(tls.SecretName) == name {
				return true
			}
		}
	}
	return false
}
