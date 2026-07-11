// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"

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
	if err := r.Get(ctx, client.ObjectKeyFromObject(translation), translation); err != nil {
		return err
	}

	status := bridgev1alpha1.IngressTranslationStatus{
		ObservedGeneration: ing.Generation,
		Conditions:         append([]metav1.Condition(nil), translation.Status.Conditions...),
		GeneratedResources: generatedReferences(desired),
		Issues:             statusIssues(plan.Issues),
	}
	now := metav1.Now()
	if plan.Fatal() {
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: "Translated", Status: metav1.ConditionFalse, Reason: "UnsupportedIngress",
			Message: "one or more Ingress fields cannot be reproduced safely", ObservedGeneration: ing.Generation, LastTransitionTime: now,
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
		readyStatus, reason, message, err := r.generatedReady(ctx, desired)
		if err != nil {
			return err
		}
		apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: "Ready", Status: readyStatus, Reason: reason, Message: message,
			ObservedGeneration: ing.Generation, LastTransitionTime: now,
		})
	}

	if equality.Semantic.DeepEqual(translation.Status, status) {
		return nil
	}
	before := translation.DeepCopy()
	translation.Status = status
	return r.Status().Patch(ctx, translation, client.MergeFrom(before))
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
		foundParent := false
		for _, parent := range current.Status.Parents {
			if parent.ControllerName != nginxGatewayController {
				continue
			}
			if parent.ParentRef.Name != gatewayv1.ObjectName(r.Config.GatewayName) {
				continue
			}
			if parent.ParentRef.Namespace != nil && string(*parent.ParentRef.Namespace) != r.Config.GatewayNamespace {
				continue
			}
			foundParent = true
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
		if !foundParent {
			return metav1.ConditionUnknown, "RoutePending", fmt.Sprintf("HTTPRoute %s has no status for the target Gateway", route.Name), nil
		}
	}
	return metav1.ConditionTrue, "Programmed", "Gateway, generated routes, filters, and policies are programmed", nil
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
