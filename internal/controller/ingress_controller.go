// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	ngfv1alpha1 "github.com/nginx/nginx-gateway-fabric/v2/apis/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bridgev1alpha1 "github.com/zyno-io/ingress-nginx-gateway-bridge/api/v1alpha1"
	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/translator"
)

const (
	finalizerName = "gateway.zyno.io/cleanup"
	fieldManager  = "ingress-nginx-gateway-bridge"
)

var globalReconcileKey = types.NamespacedName{Name: "ingress-nginx-gateway-bridge-global-sync"}

// IngressReconciler continuously projects selected Ingresses into Gateway API resources.
type IngressReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Config Config
}

// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=services;configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways;httproutes;referencegrants;backendtlspolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.nginx.org,resources=clientsettingspolicies;proxysettingspolicies;authenticationfilters;snippetsfilters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.zyno.io,resources=ingresstranslations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.zyno.io,resources=ingresstranslations/status,verbs=get;update;patch

func (r *IngressReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("ingress", request.NamespacedName)
	ctx = ctrl.LoggerInto(ctx, log)
	if request.NamespacedName == globalReconcileKey {
		if r.Config.ManageGateway {
			_, err := r.reconcileManagedGateway(ctx)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var ing networkingv1.Ingress
	if err := r.Get(ctx, request.NamespacedName, &ing); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		if err := r.pruneSource(ctx, request.NamespacedName, nil, true); err != nil {
			return ctrl.Result{}, err
		}
		if r.Config.ManageGateway {
			_, err = r.reconcileManagedGateway(ctx)
		}
		return ctrl.Result{}, err
	}

	if !ing.DeletionTimestamp.IsZero() {
		if err := r.pruneSource(ctx, request.NamespacedName, nil, true); err != nil {
			return ctrl.Result{}, err
		}
		if r.Config.ManageGateway {
			if _, err := r.reconcileManagedGateway(ctx); err != nil {
				return ctrl.Result{}, err
			}
		}
		if controllerutil.ContainsFinalizer(&ing, finalizerName) || ing.Labels[translator.TranslationStatusLabel] != "" {
			before := ing.DeepCopy()
			controllerutil.RemoveFinalizer(&ing, finalizerName)
			delete(ing.Labels, translator.TranslationStatusLabel)
			if err := r.Patch(ctx, &ing, client.MergeFrom(before)); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !r.Config.Selected(&ing) {
		if err := r.pruneSource(ctx, request.NamespacedName, nil, true); err != nil {
			return ctrl.Result{}, err
		}
		if r.Config.ManageGateway {
			if _, err := r.reconcileManagedGateway(ctx); err != nil {
				return ctrl.Result{}, err
			}
		}
		if controllerutil.ContainsFinalizer(&ing, finalizerName) || ing.Labels[translator.TranslationStatusLabel] != "" {
			before := ing.DeepCopy()
			controllerutil.RemoveFinalizer(&ing, finalizerName)
			delete(ing.Labels, translator.TranslationStatusLabel)
			if err := r.Patch(ctx, &ing, client.MergeFrom(before)); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&ing, finalizerName) {
		before := ing.DeepCopy()
		controllerutil.AddFinalizer(&ing, finalizerName)
		if err := r.Patch(ctx, &ing, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, err
		}
	}

	options := translator.Options{
		Gateway: translator.GatewayOptions{
			Namespace:        r.Config.GatewayNamespace,
			Name:             r.Config.GatewayName,
			HTTPSectionName:  r.Config.HTTPSectionName,
			HTTPSSectionName: r.Config.HTTPSSectionName,
			ManagedListeners: r.Config.ManageGateway,
		},
		AllowSnippets: r.Config.AllowSnippets,
		Strict:        r.Config.Strict,
	}
	var gatewayPlan translator.GatewayPlan
	if r.Config.ManageGateway {
		var err error
		gatewayPlan, err = r.reconcileManagedGateway(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		options.TLSHosts = gatewayPlan.TLSHosts
		options.Gateway.TLSSections = gatewayPlan.TLSSections
	}
	settingsAsSnippets, err := r.requiresSettingsSnippets(ctx, &ing)
	if err != nil {
		return ctrl.Result{}, err
	}
	options.SettingsAsSnippets = settingsAsSnippets
	plan := translator.Translate(ctx, &ing, options, r.resolveServicePort, r.resolveConfigMap)
	if r.Config.ManageGateway {
		plan.Issues = append(plan.Issues, gatewayPlan.Issues[request.NamespacedName]...)
	}

	desired := make([]client.Object, 0)
	if !plan.Fatal() {
		desired = planObjects(&plan)
		for _, object := range desired {
			if err := controllerutil.SetControllerReference(&ing, object, r.Scheme); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.apply(ctx, object); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	if err := r.pruneSource(ctx, request.NamespacedName, desired, false); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileTranslationStatus(ctx, &ing, plan, desired); err != nil {
		return ctrl.Result{}, err
	}
	if r.Config.UpdateIngressStatus && !plan.Fatal() {
		if err := r.mirrorIngressStatus(ctx, &ing, desired); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *IngressReconciler) reconcileManagedGateway(ctx context.Context) (translator.GatewayPlan, error) {
	var ingressList networkingv1.IngressList
	if err := r.List(ctx, &ingressList); err != nil {
		return translator.GatewayPlan{}, err
	}
	selected := make([]networkingv1.Ingress, 0, len(ingressList.Items))
	for idx := range ingressList.Items {
		if r.Config.Selected(&ingressList.Items[idx]) && ingressList.Items[idx].DeletionTimestamp.IsZero() {
			selected = append(selected, ingressList.Items[idx])
		}
	}
	plan := translator.BuildManagedGateway(selected, translator.ManagedGatewayOptions{
		Namespace:         r.Config.GatewayNamespace,
		Name:              r.Config.GatewayName,
		ClassName:         r.Config.GatewayClassName,
		NginxProxyName:    r.Config.NginxProxyName,
		AllowListenerSets: r.Config.AllowListenerSets,
		HTTPSectionName:   r.Config.HTTPSectionName,
		HTTPSSectionName:  r.Config.HTTPSSectionName,
	})
	if err := r.apply(ctx, &plan.Gateway); err != nil {
		return plan, err
	}

	desiredGrants := make(map[types.NamespacedName]struct{}, len(plan.ReferenceGrants))
	for idx := range plan.ReferenceGrants {
		grant := &plan.ReferenceGrants[idx]
		if err := r.apply(ctx, grant); err != nil {
			return plan, err
		}
		desiredGrants[client.ObjectKeyFromObject(grant)] = struct{}{}
	}

	var current gatewayv1.ReferenceGrantList
	if err := r.List(ctx, &current, client.MatchingLabels{
		translator.ManagedByLabel: translator.ControllerName,
		translator.GatewayLabel:   translator.GatewayLabelValue(r.Config.GatewayNamespace, r.Config.GatewayName),
	}); err != nil {
		return plan, err
	}
	for idx := range current.Items {
		grant := &current.Items[idx]
		if _, keep := desiredGrants[client.ObjectKeyFromObject(grant)]; !keep {
			if err := r.Delete(ctx, grant); client.IgnoreNotFound(err) != nil {
				return plan, err
			}
		}
	}
	return plan, nil
}

func (r *IngressReconciler) apply(ctx context.Context, object client.Object) error {
	key := client.ObjectKeyFromObject(object)
	current := object.DeepCopyObject().(client.Object)
	err := r.Get(ctx, key, current)
	if err == nil && current.GetLabels()[translator.ManagedByLabel] != translator.ControllerName {
		return fmt.Errorf("refusing to adopt unmanaged %T %s", object, key)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	data, err := json.Marshal(object)
	if err != nil {
		return fmt.Errorf("marshal apply configuration for %T %s: %w", object, key, err)
	}
	return r.Patch(ctx, object, client.RawPatch(types.ApplyPatchType, data), client.FieldOwner(fieldManager))
}

func (r *IngressReconciler) pruneSource(
	ctx context.Context,
	source types.NamespacedName,
	desired []client.Object,
	includeStatus bool,
) error {
	keep := make(map[string]struct{}, len(desired))
	for _, object := range desired {
		keep[fmt.Sprintf("%T/%s/%s", object, object.GetNamespace(), object.GetName())] = struct{}{}
	}
	labels := client.MatchingLabels{
		translator.ManagedByLabel:       translator.ControllerName,
		translator.SourceNamespaceLabel: source.Namespace,
		translator.SourceNameLabel:      translator.SourceNameLabelValue(source.Name),
	}
	lists := []client.ObjectList{
		&gatewayv1.HTTPRouteList{},
		&gatewayv1.BackendTLSPolicyList{},
		&ngfv1alpha1.ClientSettingsPolicyList{},
		&ngfv1alpha1.ProxySettingsPolicyList{},
		&ngfv1alpha1.AuthenticationFilterList{},
		&ngfv1alpha1.SnippetsFilterList{},
	}
	if includeStatus {
		lists = append(lists, &bridgev1alpha1.IngressTranslationList{})
	}
	var allErrors []error
	for _, list := range lists {
		if err := r.List(ctx, list, client.InNamespace(source.Namespace), labels); err != nil {
			allErrors = append(allErrors, err)
			continue
		}
		if err := deleteListItems(ctx, r.Client, list, keep); err != nil {
			allErrors = append(allErrors, err)
		}
	}
	return errors.Join(allErrors...)
}

func deleteListItems(ctx context.Context, k8sClient client.Client, list client.ObjectList, keep map[string]struct{}) error {
	items, err := apimeta.ExtractList(list)
	if err != nil {
		return err
	}
	var allErrors []error
	for _, item := range items {
		object, ok := item.(client.Object)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%T/%s/%s", object, object.GetNamespace(), object.GetName())
		if _, exists := keep[key]; exists {
			continue
		}
		if err := k8sClient.Delete(ctx, object); client.IgnoreNotFound(err) != nil {
			allErrors = append(allErrors, err)
		}
	}
	return errors.Join(allErrors...)
}

func planObjects(plan *translator.Plan) []client.Object {
	objects := make([]client.Object, 0,
		len(plan.HTTPRoutes)+len(plan.BackendTLSPolicies)+len(plan.ClientSettingsPolicies)+len(plan.ProxySettingsPolicies)+
			len(plan.AuthenticationFilters)+len(plan.SnippetsFilters),
	)
	for idx := range plan.HTTPRoutes {
		objects = append(objects, &plan.HTTPRoutes[idx])
	}
	for idx := range plan.BackendTLSPolicies {
		objects = append(objects, &plan.BackendTLSPolicies[idx])
	}
	for idx := range plan.ClientSettingsPolicies {
		objects = append(objects, &plan.ClientSettingsPolicies[idx])
	}
	for idx := range plan.ProxySettingsPolicies {
		objects = append(objects, &plan.ProxySettingsPolicies[idx])
	}
	for idx := range plan.AuthenticationFilters {
		objects = append(objects, &plan.AuthenticationFilters[idx])
	}
	for idx := range plan.SnippetsFilters {
		objects = append(objects, &plan.SnippetsFilters[idx])
	}
	return objects
}

func (r *IngressReconciler) resolveServicePort(
	ctx context.Context,
	namespace, serviceName, portName string,
) (int32, error) {
	var service corev1.Service
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: serviceName}, &service); err != nil {
		return 0, fmt.Errorf("resolve named port %q on Service %s/%s: %w", portName, namespace, serviceName, err)
	}
	for _, port := range service.Spec.Ports {
		if port.Name == portName {
			return port.Port, nil
		}
	}
	return 0, fmt.Errorf("service %s/%s has no port named %q", namespace, serviceName, portName)
}

func (r *IngressReconciler) resolveConfigMap(
	ctx context.Context,
	namespace, name string,
) (map[string]string, error) {
	var configMap corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &configMap); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(configMap.Data))
	for key, value := range configMap.Data {
		result[key] = value
	}
	return result, nil
}

func (r *IngressReconciler) serviceToIngresses(ctx context.Context, object client.Object) []ctrl.Request {
	service, ok := object.(*corev1.Service)
	if !ok {
		return nil
	}
	var ingresses networkingv1.IngressList
	if err := r.List(ctx, &ingresses, client.InNamespace(service.Namespace)); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0)
	for idx := range ingresses.Items {
		if ingressReferencesService(&ingresses.Items[idx], service.Name) {
			requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&ingresses.Items[idx])})
		}
	}
	return requests
}

func (r *IngressReconciler) configMapToIngresses(ctx context.Context, object client.Object) []ctrl.Request {
	configMap, ok := object.(*corev1.ConfigMap)
	if !ok {
		return nil
	}
	var ingresses networkingv1.IngressList
	if err := r.List(ctx, &ingresses, client.InNamespace(configMap.Namespace)); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0)
	for idx := range ingresses.Items {
		reference := strings.TrimSpace(ingresses.Items[idx].Annotations["nginx.ingress.kubernetes.io/auth-proxy-set-headers"])
		if reference == configMap.Name || reference == configMap.Namespace+"/"+configMap.Name {
			requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&ingresses.Items[idx])})
		}
	}
	return requests
}

func ingressReferencesService(ing *networkingv1.Ingress, service string) bool {
	if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil && ing.Spec.DefaultBackend.Service.Name == service {
		return true
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil && path.Backend.Service.Name == service {
				return true
			}
		}
	}
	return false
}

func (r *IngressReconciler) gatewayToIngresses(ctx context.Context, object client.Object) []ctrl.Request {
	gateway, ok := object.(*gatewayv1.Gateway)
	if !ok || gateway.Namespace != r.Config.GatewayNamespace || gateway.Name != r.Config.GatewayName {
		return nil
	}
	return append(r.allSelectedIngresses(ctx), ctrl.Request{NamespacedName: globalReconcileKey})
}

func (r *IngressReconciler) managedGrantToIngresses(ctx context.Context, object client.Object) []ctrl.Request {
	labels := object.GetLabels()
	if labels[translator.ManagedByLabel] != translator.ControllerName ||
		labels[translator.GatewayLabel] != translator.GatewayLabelValue(r.Config.GatewayNamespace, r.Config.GatewayName) {
		return nil
	}
	return append(r.allSelectedIngresses(ctx), ctrl.Request{NamespacedName: globalReconcileKey})
}

func (r *IngressReconciler) ingressToNamespaceIngresses(ctx context.Context, object client.Object) []ctrl.Request {
	ingress, ok := object.(*networkingv1.Ingress)
	if !ok {
		return nil
	}
	var ingresses networkingv1.IngressList
	if err := r.List(ctx, &ingresses, client.InNamespace(ingress.Namespace)); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(ingresses.Items))
	for idx := range ingresses.Items {
		if r.Config.Selected(&ingresses.Items[idx]) {
			requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&ingresses.Items[idx])})
		}
	}
	return requests
}

func (r *IngressReconciler) requiresSettingsSnippets(ctx context.Context, ingress *networkingv1.Ingress) (bool, error) {
	var ingresses networkingv1.IngressList
	if err := r.List(ctx, &ingresses, client.InNamespace(ingress.Namespace)); err != nil {
		return false, err
	}
	footprints := ingressRouteFootprints(ingress)
	for idx := range ingresses.Items {
		candidate := &ingresses.Items[idx]
		if candidate.Name == ingress.Name || !candidate.DeletionTimestamp.IsZero() || !r.Config.Selected(candidate) {
			continue
		}
		for footprint := range ingressRouteFootprints(candidate) {
			if _, overlaps := footprints[footprint]; overlaps {
				return true, nil
			}
		}
	}
	return false, nil
}

func ingressRouteFootprints(ingress *networkingv1.Ingress) map[string]struct{} {
	result := make(map[string]struct{})
	firstPaths := make([]string, 0)
	firstHost := ""
	haveFirstHost := false
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(rule.Host))
		if !haveFirstHost {
			firstHost = host
			haveFirstHost = true
		}
		for _, path := range rule.HTTP.Paths {
			value := path.Path
			if value == "" {
				value = "/"
			}
			result[host+"\x00"+value] = struct{}{}
			if host == firstHost {
				firstPaths = append(firstPaths, value)
			}
		}
	}
	if ingress.Spec.DefaultBackend != nil {
		result["\x00/"] = struct{}{}
	}
	for _, alias := range strings.Split(ingress.Annotations["nginx.ingress.kubernetes.io/server-alias"], ",") {
		alias = strings.ToLower(strings.TrimSpace(alias))
		if alias == "" {
			continue
		}
		for _, path := range firstPaths {
			result[alias+"\x00"+path] = struct{}{}
		}
	}
	return result
}

func (r *IngressReconciler) allSelectedIngresses(ctx context.Context) []ctrl.Request {
	var ingresses networkingv1.IngressList
	if err := r.List(ctx, &ingresses); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(ingresses.Items))
	for idx := range ingresses.Items {
		if r.Config.Selected(&ingresses.Items[idx]) {
			requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&ingresses.Items[idx])})
		}
	}
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].String() < requests[j].String()
	})
	return requests
}

// SetupWithManager registers watches. Reconciliation is intentionally serialized because managed Gateway listeners are global state.
func (r *IngressReconciler) SetupWithManager(manager ctrl.Manager) error {
	startup := make(chan event.GenericEvent, 1)
	startup <- event.GenericEvent{Object: &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: globalReconcileKey.Name},
	}}
	return ctrl.NewControllerManagedBy(manager).
		For(&networkingv1.Ingress{}).
		Watches(
			&networkingv1.Ingress{},
			handler.EnqueueRequestsFromMapFunc(r.ingressToNamespaceIngresses),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{})),
		).
		Owns(&gatewayv1.HTTPRoute{}).
		Owns(&gatewayv1.BackendTLSPolicy{}).
		Owns(&ngfv1alpha1.ClientSettingsPolicy{}).
		Owns(&ngfv1alpha1.ProxySettingsPolicy{}).
		Owns(&ngfv1alpha1.AuthenticationFilter{}).
		Owns(&ngfv1alpha1.SnippetsFilter{}).
		Owns(&bridgev1alpha1.IngressTranslation{}).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.serviceToIngresses)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.configMapToIngresses)).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.gatewayToIngresses)).
		Watches(&gatewayv1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(r.managedGrantToIngresses)).
		WatchesRawSource(source.Channel(startup, &handler.EnqueueRequestForObject{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}
