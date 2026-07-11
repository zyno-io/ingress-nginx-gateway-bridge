# Hot-swap runbook

This runbook keeps the source Ingress manifests unchanged while replacing the serving controller.

## 1. Install NGINX Gateway Fabric

Install Gateway API 1.5 and NGF 2.6.x. The default bridge configuration expects a `GatewayClass` named `nginx`.

Enable NGF snippets because external auth, capture rewrites, and request-buffering compatibility use `SnippetsFilter`:

```yaml
nginxGateway:
  snippets:
    enable: true
```

Keep the NGF Service address separate from ingress-nginx during preflight.

If any backend is an `ExternalName` Service, create an NGF `NginxProxy` in the Gateway namespace with the cluster DNS Service IP, then set `controller.gateway.nginxProxyName`:

```yaml
apiVersion: gateway.nginx.org/v1alpha2
kind: NginxProxy
metadata:
  name: bridge-dns
  namespace: nginx-gateway
spec:
  dnsResolver:
    addresses:
      - type: IPAddress
        value: <cluster-dns-service-ip>
---
controller:
  gateway:
    nginxProxyName: bridge-dns
```

## 2. Run the bridge without changing Ingress status

```yaml
controller:
  updateIngressStatus: false
  strict: true
  allowSnippets: false
```

The bridge will build the Gateway data plane while ingress-nginx continues serving existing traffic. Because the original Ingress resources remain present, cert-manager's Ingress shim can continue maintaining their TLS Secrets.

## 3. Clear translation errors

```sh
kubectl get ingresstranslations.gateway.zyno.io -A
kubectl get ingresstranslations.gateway.zyno.io -A -o yaml
kubectl get gateway -n nginx-gateway ingress-nginx -o yaml
kubectl get httproute -A
```

Do not cut traffic while any selected `IngressTranslation` has `Translated=False`, `Ready=False`, or `Ready=Unknown`. The readiness check includes the Gateway, HTTPRoutes, BackendTLSPolicies, NGF client/proxy policies, and NGF authentication/snippet filters.

Review every source-provided `auth-snippet`, `configuration-snippet`, and `server-snippet`. Only then enable:

```yaml
controller:
  allowSnippets: true
```

## 4. Exercise the NGF address directly

Update application NetworkPolicies before testing. Any policy that currently admits only the `ingress-nginx` namespace must also admit pods from the configured Gateway namespace (the NGF data plane runs there). Keep both sources allowed during preflight; remove the ingress-nginx allowance after cutover.

For each hostname, send requests to the NGF load-balancer address while retaining the production Host header and TLS SNI. Verify:

- TLS certificate selection
- Redirect behavior
- Authentication and propagated identity headers
- CORS preflights
- Upload limits
- Long-running requests and streaming/buffering behavior
- Header canaries and regex rewrites

## 5. Cut over

Ensure ingress-nginx and the bridge do not fight over Ingress status:

1. Stop ingress-nginx reconciliation or disable its status updates.
2. Set `controller.updateIngressStatus=true` on the bridge.
3. Confirm Ingress status contains the NGF address. The bridge leaves the previous address intact until that Ingress's complete translation is ready and NGF reports `Programmed=True` with a non-empty address.
4. Confirm external-dns or the platform load-balancer has switched traffic.
5. Monitor NGF route and policy conditions.

Rollback consists of restoring ingress-nginx, disabling bridge status updates, and restoring the previous address. The Ingress manifests remain unchanged.

## 6. Decommission safely

Do not uninstall the bridge while selected Ingresses retain its finalizer. First opt them out while the controller is running, or redeploy with classless watching disabled and an empty class allowlist. Confirm:

```sh
kubectl get ingress -A -o jsonpath='{range .items[?(@.metadata.finalizers)]}{.metadata.namespace}/{.metadata.name}{" "}{.metadata.finalizers}{"\n"}{end}'
```

After generated resources and `gateway.zyno.io/cleanup` finalizers are gone, uninstall the chart.
