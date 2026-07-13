// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"strings"

	ngfv1alpha1 "github.com/nginx/nginx-gateway-fabric/v2/apis/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bridgev1alpha1 "github.com/zyno-io/ingress-nginx-gateway-bridge/api/v1alpha1"
	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))
	utilruntime.Must(ngfv1alpha1.AddToScheme(scheme))
	utilruntime.Must(bridgev1alpha1.AddToScheme(scheme))
}

func main() {
	var config controller.Config
	var ingressClasses string
	var metricsAddress, probeAddress string
	var leaderElect bool

	flag.StringVar(&config.GatewayNamespace, "gateway-namespace", "nginx-gateway", "Namespace containing the target Gateway.")
	flag.StringVar(&config.GatewayName, "gateway-name", "ingress-nginx", "Name of the target Gateway.")
	flag.StringVar(&config.GatewayClassName, "gateway-class-name", "nginx", "GatewayClass used when --manage-gateway is enabled.")
	flag.StringVar(&config.NginxProxyName, "nginx-proxy-name", "", "Optional same-namespace NginxProxy referenced by a managed Gateway (required for ExternalName Service DNS resolution).")
	flag.BoolVar(&config.ManageGateway, "manage-gateway", true, "Create the target Gateway and derive its listeners from selected Ingresses.")
	flag.BoolVar(&config.AllowListenerSets, "allow-listener-sets", false, "Allow ListenerSets from the managed Gateway's namespace.")
	flag.StringVar(&config.HTTPSectionName, "http-section-name", "http", "HTTP listener section name.")
	flag.StringVar(&config.HTTPSSectionName, "https-section-name", "https", "HTTPS listener section name used in route-only mode.")
	flag.BoolVar(&config.WatchIngressWithoutClass, "watch-ingress-without-class", true, "Translate Ingresses with no class.")
	flag.StringVar(&ingressClasses, "ingress-classes", "nginx", "Comma-separated Ingress class names to translate; optional when watching classless Ingresses.")
	flag.BoolVar(&config.AllowSnippets, "allow-snippets", false, "Allow source auth/configuration/server snippets to enter generated NGF SnippetsFilters.")
	flag.BoolVar(&config.Strict, "strict", true, "Reject Ingresses containing unknown ingress-nginx annotations.")
	flag.BoolVar(&config.UpdateIngressStatus, "update-ingress-status", true, "Mirror the target Gateway address into selected Ingress status.")
	flag.StringVar(&metricsAddress, "metrics-bind-address", ":8080", "Address for the metrics endpoint; use 0 to disable.")
	flag.StringVar(&probeAddress, "health-probe-bind-address", ":8081", "Address for health probes.")
	flag.BoolVar(&leaderElect, "leader-elect", true, "Enable leader election.")

	logOptions := zap.Options{Development: false}
	logOptions.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOptions)))

	config.IngressClasses = make(map[string]struct{})
	for _, class := range strings.Split(ingressClasses, ",") {
		if class = strings.TrimSpace(class); class != "" {
			config.IngressClasses[class] = struct{}{}
		}
	}
	if config.GatewayNamespace == "" || config.GatewayName == "" {
		setupLog.Error(nil, "gateway-namespace and gateway-name must not be empty")
		os.Exit(1)
	}
	if config.ManageGateway && config.GatewayClassName == "" {
		setupLog.Error(nil, "gateway-class-name must not be empty when manage-gateway is enabled")
		os.Exit(1)
	}

	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddress},
		HealthProbeBindAddress: probeAddress,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "ingress-nginx-gateway-bridge.gateway.zyno.io",
	})
	if err != nil {
		setupLog.Error(err, "create manager")
		os.Exit(1)
	}

	reconciler := &controller.IngressReconciler{Client: manager.GetClient(), Scheme: manager.GetScheme(), Config: config}
	if err := reconciler.SetupWithManager(manager); err != nil {
		setupLog.Error(err, "register Ingress controller")
		os.Exit(1)
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "register health check")
		os.Exit(1)
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "register readiness check")
		os.Exit(1)
	}

	setupLog.Info("starting controller",
		"gateway", config.GatewayNamespace+"/"+config.GatewayName,
		"manageGateway", config.ManageGateway,
		"allowListenerSets", config.AllowListenerSets,
		"watchClassless", config.WatchIngressWithoutClass,
		"ingressClasses", ingressClasses,
		"strict", config.Strict,
		"allowSnippets", config.AllowSnippets,
		"updateIngressStatus", config.UpdateIngressStatus,
	)
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "run manager")
		os.Exit(1)
	}
}
