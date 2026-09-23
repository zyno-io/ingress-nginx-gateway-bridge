// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"sort"

	ngfv1alpha1 "github.com/nginx/nginx-gateway-fabric/v2/apis/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bridgev1alpha1 "github.com/zyno-io/ingress-nginx-gateway-bridge/api/v1alpha1"
	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

const nginxGatewayController = gatewayv1.GatewayController("gateway.nginx.org/nginx-gateway-controller")

func (r *IngressReconciler) reconcileTranslationStatus(
	ctx context.Context,
	ing *networkingv1.Ingress,
	plan translator.Plan,
	desired []client.Object,
) error {
	translation := &bridgev1alpha1.IngressTranslation{
		TypeMeta: metav1.TypeMeta{APIVersion: bridgev1alpha1.GroupVersion.String(), Kind: "IngressTranslation"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ing.Name,
			Namespace: ing.Namespace,
			Labels: map[string]string{
				translator.ManagedByLabel:       translator.ControllerName,
				translator.SourceNameLabel:      translator.SourceNameLabelValue(ing.Name),
				translator.SourceNamespaceLabel: ing.Namespace,
				translator.SourceUIDLabel:       string(ing.UID),
			},
		},
		Spec: bridgev1alpha1.IngressTranslationSpec{IngressName: ing.Name},
	}
	if err := controllerutil.SetControllerReference(ing, translation, r.Scheme); err != nil {
		return err
	}
	if err := r.apply(ctx, translation); err != nil {
		return err
	}
	// Patch decodes the API server response back into translation, including
	// existing status. Reading it again through the informer cache can race a
	// newly created object and cause a needless NotFound reconciliation error.

	status := bridgev1alpha1.IngressTranslationStatus{
		ObservedGeneration: ing.Generation,
		Conditions:         append([]metav1.Condition(nil), translation.Status.Conditions...),
		GeneratedResources: generatedReferences(desired),
		Issues:             statusIssues(plan.Issues),
	}
	labelValue := translator.TranslationStatusFailed
	now := metav1.Now()
	if plan.Fatal() {
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: "Translated", Status: metav1.ConditionFalse, Reason: "UnsupportedIngress",
			Message: "one or more Ingress fields cannot be reproduced faithfully", ObservedGeneration: ing.Generation, LastTransitionTime: now,
		})
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: "Ready", Status: metav1.ConditionFalse, Reason: "TranslationFailed",
			Message: "generated routing has been removed", ObservedGeneration: ing.Generation, LastTransitionTime: now,
		})
	} else {
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: "Translated", Status: metav1.ConditionTrue, Reason: "TranslationSucceeded",
			Message: "Ingress was translated without fatal compatibility issues", ObservedGeneration: ing.Generation, LastTransitionTime: now,
		})
		var readyStatus metav1.ConditionStatus
		var reason, message string
		var err error
		if plan.DelegatedTo != "" {
			readyStatus, reason, message, err = r.delegatedReady(ctx, ing.Namespace, plan.DelegatedTo)
		} else {
			readyStatus, reason, message, err = r.generatedReady(ctx, desired)
		}
		if err != nil {
			return err
		}
		labelValue = translationStatusLabelValue(readyStatus)
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: "Ready", Status: readyStatus, Reason: reason, Message: message,
			ObservedGeneration: ing.Generation, LastTransitionTime: now,
		})
	}

	if !equality.Semantic.DeepEqual(translation.Status, status) {
		before := translation.DeepCopy()
		translation.Status = status
		if err := r.Status().Patch(ctx, translation, client.MergeFrom(before)); err != nil {
			return err
		}
	}
	return r.patchIngressTranslationLabel(ctx, ing, labelValue)
}

func (r *IngressReconciler) delegatedReady(
	ctx context.Context,
	namespace, primaryName string,
) (metav1.ConditionStatus, string, string, error) {
	var primary networkingv1.Ingress
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: primaryName}, &primary); err != nil {
		if apierrors.IsNotFound(err) {
			return metav1.ConditionUnknown, "DelegatedRoutePending", fmt.Sprintf("primary Ingress %s does not exist", primaryName), nil
		}
		return metav1.ConditionUnknown, "LookupFailed", "could not read primary Ingress", err
	}

	var translation bridgev1alpha1.IngressTranslation
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: primaryName}, &translation); err != nil {
		if apierrors.IsNotFound(err) {
			return metav1.ConditionUnknown, "DelegatedRoutePending", fmt.Sprintf("primary IngressTranslation %s does not exist yet", primaryName), nil
		}
		return metav1.ConditionUnknown, "LookupFailed", "could not read primary IngressTranslation", err
	}
	if translation.Status.ObservedGeneration != primary.Generation {
		return metav1.ConditionUnknown, "DelegatedRoutePending", fmt.Sprintf("primary IngressTranslation %s has not observed generation %d", primaryName, primary.Generation), nil
	}
	ready := apimeta.FindStatusCondition(translation.Status.Conditions, "Ready")
	if ready == nil || ready.ObservedGeneration != primary.Generation {
		return metav1.ConditionUnknown, "DelegatedRoutePending", fmt.Sprintf("primary IngressTranslation %s has incomplete readiness status", primaryName), nil
	}
	switch ready.Status {
	case metav1.ConditionTrue:
		return metav1.ConditionTrue, "Delegated", fmt.Sprintf("routing is consolidated into Ready primary Ingress %s", primaryName), nil
	case metav1.ConditionFalse:
		return metav1.ConditionFalse, "DelegatedRouteNotReady", fmt.Sprintf("primary IngressTranslation %s is not Ready: %s", primaryName, ready.Message), nil
	default:
		return metav1.ConditionUnknown, "DelegatedRoutePending", fmt.Sprintf("primary IngressTranslation %s is pending: %s", primaryName, ready.Message), nil
	}
}

func translationStatusLabelValue(ready metav1.ConditionStatus) string {
	if ready == metav1.ConditionTrue {
		return translator.TranslationStatusReady
	}
	if ready == metav1.ConditionUnknown {
		return translator.TranslationStatusPending
	}
	return translator.TranslationStatusFailed
}

func (r *IngressReconciler) patchIngressTranslationLabel(
	ctx context.Context,
	ing *networkingv1.Ingress,
	value string,
) error {
	if ing.Labels[translator.TranslationStatusLabel] == value {
		return nil
	}
	before := ing.DeepCopy()
	if ing.Labels == nil {
		ing.Labels = make(map[string]string)
	}
	ing.Labels[translator.TranslationStatusLabel] = value
	return r.Patch(ctx, ing, client.MergeFrom(before))
}

func (r *IngressReconciler) generatedReady(
	ctx context.Context,
	desired []client.Object,
) (metav1.ConditionStatus, string, string, error) {
	var gateway gatewayv1.Gateway
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.Config.GatewayNamespace, Name: r.Config.GatewayName}, &gateway); err != nil {
		if apierrors.IsNotFound(err) {
			return metav1.ConditionUnknown, "GatewayPending", "target Gateway does not exist yet", nil
		}
		return metav1.ConditionUnknown, "LookupFailed", "could not read target Gateway", err
	}
	programmed := apimeta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if programmed == nil || programmed.ObservedGeneration != gateway.Generation || programmed.Status == metav1.ConditionUnknown {
		return metav1.ConditionUnknown, "GatewayPending", "target Gateway has not reported Programmed", nil
	}
	if programmed.Status != metav1.ConditionTrue {
		return metav1.ConditionFalse, "GatewayNotProgrammed", programmed.Message, nil
	}

	for _, name := range desiredListenerSets(desired, r.Config.GatewayNamespace) {
		var set gatewayv1.ListenerSet
		key := types.NamespacedName{Namespace: r.Config.GatewayNamespace, Name: name}
		if err := r.Get(ctx, key, &set); err != nil {
			if apierrors.IsNotFound(err) {
				return metav1.ConditionUnknown, "ListenerSetPending", fmt.Sprintf("ListenerSet %s does not exist yet", name), nil
			}
			return metav1.ConditionUnknown, "LookupFailed", "could not read managed ListenerSet", err
		}
		for _, conditionType := range []gatewayv1.ListenerSetConditionType{
			gatewayv1.ListenerSetConditionAccepted, gatewayv1.ListenerSetConditionProgrammed,
		} {
			condition := apimeta.FindStatusCondition(set.Status.Conditions, string(conditionType))
			if condition == nil || condition.ObservedGeneration != set.Generation || condition.Status == metav1.ConditionUnknown {
				return metav1.ConditionUnknown, "ListenerSetPending", fmt.Sprintf("ListenerSet %s has not reported %s", name, conditionType), nil
			}
			if condition.Status != metav1.ConditionTrue {
				return metav1.ConditionFalse, "ListenerSetNotProgrammed", fmt.Sprintf("ListenerSet %s: %s", name, condition.Message), nil
			}
		}
	}

	for _, object := range desired {
		switch policy := object.(type) {
		case *ngfv1alpha1.ClientSettingsPolicy:
			var current ngfv1alpha1.ClientSettingsPolicy
			if err := r.Get(ctx, client.ObjectKeyFromObject(policy), &current); err != nil {
				return pendingObject("ClientSettingsPolicy", policy.Name, err)
			}
			if status, reason, message := attachedPolicyReady("ClientSettingsPolicy", policy.Name, current.Generation, current.Status); status != metav1.ConditionTrue {
				return status, reason, message, nil
			}
			continue
		case *ngfv1alpha1.ProxySettingsPolicy:
			var current ngfv1alpha1.ProxySettingsPolicy
			if err := r.Get(ctx, client.ObjectKeyFromObject(policy), &current); err != nil {
				return pendingObject("ProxySettingsPolicy", policy.Name, err)
			}
			if status, reason, message := attachedPolicyReady("ProxySettingsPolicy", policy.Name, current.Generation, current.Status); status != metav1.ConditionTrue {
				return status, reason, message, nil
			}
			continue
		case *ngfv1alpha1.AuthenticationFilter:
			var current ngfv1alpha1.AuthenticationFilter
			if err := r.Get(ctx, client.ObjectKeyFromObject(policy), &current); err != nil {
				return pendingObject("AuthenticationFilter", policy.Name, err)
			}
			if status, reason, message := extensionFilterReady("AuthenticationFilter", policy.Name, current.Generation, current.Status.Controllers); status != metav1.ConditionTrue {
				return status, reason, message, nil
			}
			continue
		case *ngfv1alpha1.SnippetsFilter:
			var current ngfv1alpha1.SnippetsFilter
			if err := r.Get(ctx, client.ObjectKeyFromObject(policy), &current); err != nil {
				return pendingObject("SnippetsFilter", policy.Name, err)
			}
			if status, reason, message := extensionFilterReady("SnippetsFilter", policy.Name, current.Generation, current.Status.Controllers); status != metav1.ConditionTrue {
				return status, reason, message, nil
			}
			continue
		}
		if policy, ok := object.(*gatewayv1.BackendTLSPolicy); ok {
			var current gatewayv1.BackendTLSPolicy
			if err := r.Get(ctx, client.ObjectKeyFromObject(policy), &current); err != nil {
				return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("BackendTLSPolicy %s is not readable yet", policy.Name), client.IgnoreNotFound(err)
			}
			if len(current.Status.Ancestors) == 0 {
				return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("BackendTLSPolicy %s has no ancestor status yet", policy.Name), nil
			}
			foundAncestor := false
			for _, ancestor := range current.Status.Ancestors {
				if ancestor.ControllerName != nginxGatewayController {
					continue
				}
				if ancestor.AncestorRef.Name != gatewayv1.ObjectName(r.Config.GatewayName) {
					continue
				}
				if ancestor.AncestorRef.Namespace != nil && string(*ancestor.AncestorRef.Namespace) != r.Config.GatewayNamespace {
					continue
				}
				foundAncestor = true
				accepted := apimeta.FindStatusCondition(ancestor.Conditions, string(gatewayv1.PolicyConditionAccepted))
				if accepted == nil || accepted.ObservedGeneration != current.Generation {
					return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("BackendTLSPolicy %s has incomplete status", policy.Name), nil
				}
				if accepted.Status != metav1.ConditionTrue {
					return metav1.ConditionFalse, "PolicyRejected", fmt.Sprintf("BackendTLSPolicy %s: %s", policy.Name, accepted.Message), nil
				}
				if resolved := apimeta.FindStatusCondition(ancestor.Conditions, "ResolvedRefs"); resolved != nil {
					if resolved.ObservedGeneration != current.Generation {
						return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("BackendTLSPolicy %s has incomplete status", policy.Name), nil
					}
					if resolved.Status != metav1.ConditionTrue {
						return metav1.ConditionFalse, "PolicyRejected", fmt.Sprintf("BackendTLSPolicy %s: %s", policy.Name, resolved.Message), nil
					}
				}
			}
			if !foundAncestor {
				return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("BackendTLSPolicy %s has no status for the target Gateway", policy.Name), nil
			}
			continue
		}
		route, ok := object.(*gatewayv1.HTTPRoute)
		if !ok {
			continue
		}
		var current gatewayv1.HTTPRoute
		if err := r.Get(ctx, client.ObjectKeyFromObject(route), &current); err != nil {
			return metav1.ConditionUnknown, "RoutePending", fmt.Sprintf("HTTPRoute %s is not readable yet", route.Name), client.IgnoreNotFound(err)
		}
		if len(current.Status.Parents) == 0 {
			return metav1.ConditionUnknown, "RoutePending", fmt.Sprintf("HTTPRoute %s has no parent status yet", route.Name), nil
		}
		for _, want := range route.Spec.ParentRefs {
			parent := matchingParentStatus(current.Status.Parents, want, current.Namespace)
			if parent == nil {
				return metav1.ConditionUnknown, "RoutePending", fmt.Sprintf("HTTPRoute %s has no status for the target Gateway", route.Name), nil
			}
			for _, conditionType := range []gatewayv1.RouteConditionType{gatewayv1.RouteConditionAccepted, gatewayv1.RouteConditionResolvedRefs} {
				condition := apimeta.FindStatusCondition(parent.Conditions, string(conditionType))
				if condition == nil || condition.ObservedGeneration != current.Generation {
					return metav1.ConditionUnknown, "RoutePending", fmt.Sprintf("HTTPRoute %s has incomplete status", route.Name), nil
				}
				if condition.Status != metav1.ConditionTrue {
					return metav1.ConditionFalse, "RouteRejected", fmt.Sprintf("HTTPRoute %s: %s", route.Name, condition.Message), nil
				}
			}
		}
	}
	return metav1.ConditionTrue, "Programmed", "Gateway, generated routes, filters, and policies are programmed", nil
}

// desiredListenerSets returns the sorted, unique names of bridge-managed
// ListenerSets that desired HTTPRoutes attach to, so their readiness can be
// folded into the managed Gateway's own. A parentRef only counts when its
// Kind is ListenerSet, its Group is unset or the Gateway API group, and its
// effective namespace (explicit, or the route's own) is the Gateway namespace.
func desiredListenerSets(desired []client.Object, gatewayNamespace string) []string {
	names := make(map[string]struct{})
	for _, object := range desired {
		route, ok := object.(*gatewayv1.HTTPRoute)
		if !ok {
			continue
		}
		for _, ref := range route.Spec.ParentRefs {
			if ref.Kind == nil || string(*ref.Kind) != translator.ListenerSetKind {
				continue
			}
			if ref.Group != nil && string(*ref.Group) != gatewayv1.GroupName {
				continue
			}
			namespace := route.Namespace
			if ref.Namespace != nil {
				namespace = string(*ref.Namespace)
			}
			if namespace != gatewayNamespace {
				continue
			}
			names[string(ref.Name)] = struct{}{}
		}
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// matchingParentStatus finds the NGF-reported parent status matching want,
// or nil if the route has not yet reported status for that specific parent.
func matchingParentStatus(parents []gatewayv1.RouteParentStatus, want gatewayv1.ParentReference, routeNamespace string) *gatewayv1.RouteParentStatus {
	for idx := range parents {
		parent := &parents[idx]
		if parent.ControllerName != nginxGatewayController {
			continue
		}
		if sameParentRef(parent.ParentRef, want, routeNamespace) {
			return parent
		}
	}
	return nil
}

// sameParentRef compares a reported ParentReference against a desired one,
// applying the same defaulting rules Gateway API defines: an absent Group is
// the Gateway API group, an absent Kind is "Gateway", and an absent
// Namespace is the route's own namespace.
func sameParentRef(have, want gatewayv1.ParentReference, routeNamespace string) bool {
	haveGroup, wantGroup := gatewayv1.GroupName, gatewayv1.GroupName
	if have.Group != nil {
		haveGroup = string(*have.Group)
	}
	if want.Group != nil {
		wantGroup = string(*want.Group)
	}
	if haveGroup != wantGroup {
		return false
	}

	haveKind, wantKind := translator.GatewayKind, translator.GatewayKind
	if have.Kind != nil {
		haveKind = string(*have.Kind)
	}
	if want.Kind != nil {
		wantKind = string(*want.Kind)
	}
	if haveKind != wantKind || have.Name != want.Name {
		return false
	}

	haveNamespace, wantNamespace := routeNamespace, routeNamespace
	if have.Namespace != nil {
		haveNamespace = string(*have.Namespace)
	}
	if want.Namespace != nil {
		wantNamespace = string(*want.Namespace)
	}
	if haveNamespace != wantNamespace {
		return false
	}

	if want.SectionName != nil && (have.SectionName == nil || *have.SectionName != *want.SectionName) {
		return false
	}
	return true
}

func pendingObject(kind, name string, err error) (metav1.ConditionStatus, string, string, error) {
	return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("%s %s is not readable yet", kind, name), client.IgnoreNotFound(err)
}

func attachedPolicyReady(kind, name string, generation int64, status gatewayv1.PolicyStatus) (metav1.ConditionStatus, string, string) {
	if len(status.Ancestors) == 0 {
		return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("%s %s has no ancestor status yet", kind, name)
	}
	foundAccepted := false
	for _, ancestor := range status.Ancestors {
		if ancestor.ControllerName != nginxGatewayController {
			continue
		}
		accepted := apimeta.FindStatusCondition(ancestor.Conditions, string(gatewayv1.PolicyConditionAccepted))
		if accepted == nil || accepted.ObservedGeneration != generation {
			continue
		}
		if accepted.Status != metav1.ConditionTrue {
			return metav1.ConditionFalse, "PolicyRejected", fmt.Sprintf("%s %s: %s", kind, name, accepted.Message)
		}
		foundAccepted = true
	}
	if foundAccepted {
		return metav1.ConditionTrue, "Programmed", ""
	}
	return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("%s %s has incomplete status", kind, name)
}

func extensionFilterReady(
	kind, name string, generation int64,
	controllers []ngfv1alpha1.ControllerStatus,
) (metav1.ConditionStatus, string, string) {
	if len(controllers) == 0 {
		return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("%s %s has no controller status yet", kind, name)
	}
	foundAccepted := false
	for _, controller := range controllers {
		if controller.ControllerName != nginxGatewayController {
			continue
		}
		accepted := apimeta.FindStatusCondition(controller.Conditions, "Accepted")
		if accepted == nil || accepted.ObservedGeneration != generation {
			continue
		}
		if accepted.Status != metav1.ConditionTrue {
			return metav1.ConditionFalse, "PolicyRejected", fmt.Sprintf("%s %s: %s", kind, name, accepted.Message)
		}
		foundAccepted = true
	}
	if foundAccepted {
		return metav1.ConditionTrue, "Programmed", ""
	}
	return metav1.ConditionUnknown, "PolicyPending", fmt.Sprintf("%s %s has incomplete status", kind, name)
}

func (r *IngressReconciler) mirrorIngressStatus(
	ctx context.Context,
	ing *networkingv1.Ingress,
	desired []client.Object,
) error {
	ready, _, _, err := r.generatedReady(ctx, desired)
	if err != nil {
		return err
	}
	if ready != metav1.ConditionTrue {
		return nil
	}
	var gateway gatewayv1.Gateway
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.Config.GatewayNamespace, Name: r.Config.GatewayName}, &gateway); err != nil {
		return client.IgnoreNotFound(err)
	}
	programmed := apimeta.FindStatusCondition(gateway.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed))
	if programmed == nil || programmed.ObservedGeneration != gateway.Generation || programmed.Status != metav1.ConditionTrue || len(gateway.Status.Addresses) == 0 {
		return nil
	}
	addresses := make([]networkingv1.IngressLoadBalancerIngress, 0, len(gateway.Status.Addresses))
	for _, address := range gateway.Status.Addresses {
		entry := networkingv1.IngressLoadBalancerIngress{}
		if address.Type != nil && *address.Type == gatewayv1.IPAddressType {
			entry.IP = address.Value
		} else {
			entry.Hostname = address.Value
		}
		addresses = append(addresses, entry)
	}
	if equality.Semantic.DeepEqual(ing.Status.LoadBalancer.Ingress, addresses) {
		return nil
	}
	before := ing.DeepCopy()
	ing.Status.LoadBalancer.Ingress = addresses
	return r.Status().Patch(ctx, ing, client.MergeFrom(before))
}

func generatedReferences(objects []client.Object) []bridgev1alpha1.ResourceReference {
	result := make([]bridgev1alpha1.ResourceReference, 0, len(objects))
	for _, object := range objects {
		gvk := object.GetObjectKind().GroupVersionKind()
		result = append(result, bridgev1alpha1.ResourceReference{
			APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind,
			Namespace: object.GetNamespace(), Name: object.GetName(),
		})
	}
	return result
}

func statusIssues(issues []translator.Issue) []bridgev1alpha1.TranslationIssue {
	result := make([]bridgev1alpha1.TranslationIssue, 0, len(issues))
	for _, issue := range issues {
		result = append(result, bridgev1alpha1.TranslationIssue{
			Severity: string(issue.Severity), Field: issue.Field, Message: issue.Message,
		})
	}
	return result
}
