# Architecture

## Sources and outputs

The controller watches selected `networking.k8s.io/v1` Ingresses cluster-wide. Each source produces one application `HTTPRoute` per hostname, plus a redirect route when TLS and ingress-nginx's default SSL redirect are active.

Keeping one hostname per route avoids widening rules across hosts: Gateway API applies every rule in an `HTTPRoute` to every hostname in that route.

Namespaced outputs are owned by the source Ingress:

- `HTTPRoute`
- `ClientSettingsPolicy`
- `ProxySettingsPolicy`
- `BackendTLSPolicy`
- `AuthenticationFilter`
- `SnippetsFilter`
- `IngressTranslation`

The shared `Gateway` cannot be owned by an Ingress in another namespace, and a certificate `ReferenceGrant` can be shared by several source Ingresses. They are therefore not source-owned; they are labeled with both the bridge identity and target Gateway identity and reconciled from the complete selected Ingress set. The target label prevents two bridge installations from pruning one another's grants. Reconciliation is serialized and a global reconciliation is queued at controller startup so stale shared state converges even when no Ingress is selected.

## Managed Gateway mode

Managed mode creates:

- One shared HTTP listener on port 80.
- One hostname-scoped HTTPS listener per exact or wildcard TLS hostname. Each listener references only its selected certificate Secret, making NGF's SNI certificate selection deterministic.
- Cross-namespace `ReferenceGrant` objects allowing that Gateway to reference application TLS Secrets.

Rules covered by an exact or wildcard TLS hostname attach to the matching hostname-scoped HTTPS listener, including sibling Ingresses for the same hostname. When a TLS entry omits `hosts`, the bridge infers the named rules on that Ingress, matching ingress-nginx's merged-host behavior. Conflicting Secrets for the same hostname are fatal for both source Ingresses. Gateway API limits a Gateway to 64 listeners, so managed mode supports up to 63 TLS hostnames alongside its HTTP listener.

The bridge owns the managed Gateway specification. It refuses to adopt a pre-existing Gateway unless it already has:

```yaml
gateway.zyno.io/managed-by: ingress-nginx-gateway-bridge
```

Use route-only mode (`controller.gateway.manage=false`) when the platform owns all listeners independently.

When an Ingress backend is an `ExternalName` Service, NGF requires DNS resolver settings in a same-namespace `NginxProxy`. Set `controller.gateway.nginxProxyName` to make the managed Gateway reference that platform-owned resource. The bridge does not create it because resolver addresses are cluster-specific.

Gateway API `ReferenceGrant` can restrict the source namespace and kind but not a specific source object name. Consequently, each generated grant permits Gateways in the configured Gateway namespace—not only the bridge Gateway—to reference that named TLS Secret. Keep the Gateway namespace platform-controlled.

## Reconciliation contract

1. Select the source by class/configuration annotations.
2. Add the cleanup finalizer.
3. Parse the complete Ingress and all ingress-nginx annotations into an internal plan.
4. Reconcile the shared Gateway listener projection.
5. If any issue is fatal, delete the source's active generated routing.
6. Otherwise, server-side apply the desired resources with a dedicated field manager.
7. Delete previously generated resources absent from the new plan.
8. Publish `IngressTranslation` conditions and issues.
9. Mirror the Gateway address into Ingress status when enabled.

Status mirroring waits until the complete translation reports ready, the Gateway reports `Programmed=True`, and the Gateway has at least one address. This preserves the previous ingress-nginx address during NGF provisioning or route/policy rejection instead of clearing or switching it prematurely.

NGF rejects a route-attached policy when another route has the same Gateway, hostname, port, and path but is not targeted by that same policy. The bridge detects these overlapping route families (including header canaries) and emits the client/proxy settings as generated `SnippetsFilter` directives for every affected Ingress. Non-overlapping routes continue to use `ClientSettingsPolicy` and `ProxySettingsPolicy`.

Services are watched so named Service port mutations retrigger translation. ConfigMaps referenced by `auth-proxy-set-headers` are also watched.

## Handoff to native Gateway API

The source Ingress remains authoritative. Before deploying a native HTTPRoute for the same hostname, opt the Ingress out:

```yaml
metadata:
  annotations:
    gateway.zyno.io/ignore: "true"
```

Wait for its generated resources and finalizer to disappear, then deploy the native route. This avoids ambiguous ownership and duplicate route precedence.

## Security boundaries

Generated external-auth and rewrite snippets are built from parsed, validated fields. Arbitrary source snippets are a separate capability and require `--allow-snippets`.

NGF also requires snippets to be enabled. Operators should restrict who may create or mutate selected Ingresses because Ingress annotations affect data-plane configuration.
