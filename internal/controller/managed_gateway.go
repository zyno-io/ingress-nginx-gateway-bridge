// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"strconv"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

// affectedIngressPriority pushes replan-triggered Ingress reconciliations
// ahead of routine work, so a listener that just moved parents does not sit
// behind an unrelated backlog before its HTTPRoute is repointed.
const affectedIngressPriority = 10

// observedListenerPlacements reconstructs listener placement from the
// cluster so a freshly started controller keeps existing listeners sticky
// instead of replanning from a blank slate. It only trusts objects already
// labeled as bridge-managed for this Gateway.
func (r *IngressReconciler) observedListenerPlacements(ctx context.Context) (map[string]translator.ListenerPlacement, error) {
	placements := make(map[string]translator.ListenerPlacement)

	var gateway gatewayv1.Gateway
	key := types.NamespacedName{Namespace: r.Config.GatewayNamespace, Name: r.Config.GatewayName}
	if err := r.Get(ctx, key, &gateway); err != nil {
		if apierrors.IsNotFound(err) {
			return placements, nil
		}
		return nil, err
	}
	if gateway.Labels[translator.ManagedByLabel] == translator.ControllerName {
		entries := make([]gatewayv1.ListenerEntry, len(gateway.Spec.Listeners))
		for idx, listener := range gateway.Spec.Listeners {
			entries[idx] = gatewayv1.ListenerEntry(listener)
		}
		recordObservedListeners(placements, gateway.Namespace, 0, entries)
	}

	if !r.Config.ListenerSetsAvailable {
		return placements, nil
	}
	var sets gatewayv1.ListenerSetList
	if err := r.List(ctx, &sets, client.InNamespace(r.Config.GatewayNamespace), client.MatchingLabels{
		translator.ManagedByLabel: translator.ControllerName,
		translator.GatewayLabel:   translator.GatewayLabelValue(r.Config.GatewayNamespace, r.Config.GatewayName),
	}); err != nil {
		return nil, err
	}
	for idx := range sets.Items {
		set := &sets.Items[idx]
		index, err := strconv.Atoi(set.Labels[translator.ListenerSetIndexLabel])
		if err != nil || index < 1 {
			continue
		}
		if set.Name != translator.ManagedListenerSetName(r.Config.GatewayName, index) {
			continue
		}
		recordObservedListeners(placements, set.Namespace, index, set.Spec.Listeners)
	}
	return placements, nil
}

// recordObservedListeners records every HTTPS, port-443 listener with a
// hostname and at least one certificate reference. A hostname observed at
// more than one index (which should not normally happen) keeps the lower one.
func recordObservedListeners(
	placements map[string]translator.ListenerPlacement,
	parentNamespace string,
	index int,
	listeners []gatewayv1.ListenerEntry,
) {
	for _, listener := range listeners {
		if listener.Protocol != gatewayv1.HTTPSProtocolType || listener.Port != 443 ||
			listener.Hostname == nil || listener.TLS == nil || len(listener.TLS.CertificateRefs) == 0 {
			continue
		}
		ref := listener.TLS.CertificateRefs[0]
		secretNamespace := parentNamespace
		if ref.Namespace != nil && string(*ref.Namespace) != "" {
			secretNamespace = string(*ref.Namespace)
		}
		hostname := string(*listener.Hostname)
		placement := translator.ListenerPlacement{
			ListenerSet: index,
			Secret:      types.NamespacedName{Namespace: secretNamespace, Name: string(ref.Name)},
		}
		if existing, exists := placements[hostname]; !exists || index < existing.ListenerSet {
			placements[hostname] = placement
		}
	}
}

// pruneListenerSets deletes bridge-managed ListenerSets for this Gateway
// that are no longer part of the desired plan.
func (r *IngressReconciler) pruneListenerSets(ctx context.Context, desired map[types.NamespacedName]struct{}) error {
	var current gatewayv1.ListenerSetList
	if err := r.List(ctx, &current, client.InNamespace(r.Config.GatewayNamespace), client.MatchingLabels{
		translator.ManagedByLabel: translator.ControllerName,
		translator.GatewayLabel:   translator.GatewayLabelValue(r.Config.GatewayNamespace, r.Config.GatewayName),
	}); err != nil {
		return err
	}
	for idx := range current.Items {
		set := &current.Items[idx]
		if _, keep := desired[client.ObjectKeyFromObject(set)]; !keep {
			if err := r.Delete(ctx, set); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// enqueueAffectedIngresses pushes every Ingress whose routes attach to a
// listener in changed onto the high-priority channel, so its HTTPRoute is
// repointed without waiting for its next natural reconciliation.
func (r *IngressReconciler) enqueueAffectedIngresses(
	ingresses []networkingv1.Ingress,
	tlsHosts map[string]struct{},
	changed map[string]struct{},
) {
	if len(changed) == 0 || r.affectedIngresses == nil {
		return
	}
	for idx := range ingresses {
		ing := &ingresses[idx]
		affected := false
		for _, host := range translator.RouteTLSHostnames(ing, tlsHosts) {
			if _, ok := changed[host]; ok {
				affected = true
				break
			}
		}
		if !affected {
			continue
		}
		evt := event.GenericEvent{Object: &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: ing.Namespace, Name: ing.Name},
		}}
		select {
		case r.affectedIngresses <- evt:
		default:
			// The channel is generously sized; a full channel means an
			// unusually large replan is already in flight. Drop rather than
			// block reconciliation, since the Ingress will still converge on
			// its next regular watch event.
		}
	}
}

// prioritizedIngressHandler enqueues affected-Ingress events ahead of
// routine work when the controller's workqueue supports priorities, and
// falls back to a plain enqueue otherwise.
func prioritizedIngressHandler() handler.EventHandler {
	return handler.Funcs{
		GenericFunc: func(_ context.Context, e event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(e.Object)}
			if pq, ok := q.(priorityqueue.PriorityQueue[reconcile.Request]); ok {
				priority := affectedIngressPriority
				pq.AddWithOpts(priorityqueue.AddOpts{Priority: &priority}, request)
				return
			}
			q.Add(request)
		},
	}
}

// managedListenerSetToIngresses requeues every selected Ingress (plus the
// global sync key) when a bridge-managed ListenerSet in the Gateway
// namespace changes. A ListenerSet outside that namespace cannot be one we manage.
func (r *IngressReconciler) managedListenerSetToIngresses(ctx context.Context, object client.Object) []ctrl.Request {
	if object.GetNamespace() != r.Config.GatewayNamespace {
		return nil
	}
	return r.managedGrantToIngresses(ctx, object)
}

// listenerSetChanged limits ListenerSet update events to changes that could
// affect status derived from it: spec (Generation), identifying Labels, or
// reported Conditions. Status-only churn like AttachedRoutes/Listeners
// counts is ignored to avoid reconciling on every route attach/detach.
var listenerSetChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldSet, ok := e.ObjectOld.(*gatewayv1.ListenerSet)
		if !ok {
			return true
		}
		newSet, ok := e.ObjectNew.(*gatewayv1.ListenerSet)
		if !ok {
			return true
		}
		if oldSet.Generation != newSet.Generation {
			return true
		}
		if !equality.Semantic.DeepEqual(oldSet.Labels, newSet.Labels) {
			return true
		}
		return !equality.Semantic.DeepEqual(oldSet.Status.Conditions, newSet.Status.Conditions)
	},
}
