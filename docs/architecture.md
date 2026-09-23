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
- One HTTPS listener per exact TLS hostname, or one shared HTTPS listener per wildcard certificate covering several declared hostnames (wildcard collapse, below). Each listener references only its selected certificate Secret, making NGF's SNI certificate selection deterministic.
- Cross-namespace `ReferenceGrant` objects allowing the Gateway—and, while the `ListenerSet` API is available, ListenerSets in its namespace—to reference application TLS Secrets.

Rules covered by an exact or wildcard TLS hostname attach to the matching HTTPS listener, including sibling Ingresses for the same hostname. When a TLS entry omits `hosts`, the bridge infers the named rules on that Ingress, matching ingress-nginx's merged-host behavior. Conflicting Secrets for the same hostname are fatal for both source Ingresses.

### Wildcard collapse

When `controller.gateway.collapseWildcardCertificates` is enabled (the default), the bridge parses each referenced TLS Secret's leaf certificate. A declared hostname is collapsed onto a shared wildcard listener when the certificate carries a matching wildcard SAN exactly one label up—`a.b.s24.dev` is covered by `*.b.s24.dev`, but not by `*.s24.dev`. `TLSHosts` and the Ingress status conditions always describe declared hostnames only; a wildcard listener's own hostname is exposed there only if some Ingress declared it directly.

Several Ingresses whose TLS Secrets carry byte-identical certificate chains share one wildcard listener. When declared hostnames under the same wildcard carry genuinely different certificates, the bridge picks one certificate "class" to serve the shared listener—minimizing how many listeners change parent versus the previous plan, then preferring the class covering more hostnames, then the lexicographically first Secret—and every hostname outside that class falls back to its own exact listener. Only a fingerprint (SHA-256 over the DER chain) and the certificate's wildcard SANs are ever kept in memory; no key or certificate material is retained.

### Overflow ListenerSets

Gateway API limits a Gateway to 64 listeners. Managed mode reserves one for HTTP and places up to 63 HTTPS listeners directly on the Gateway; once that fills, further HTTPS listeners go into bridge-managed `ListenerSet` overflow resources named `<gateway>-<index>`, each holding up to 64 listeners and requiring the `gateway.networking.k8s.io/v1` `ListenerSet` CRD (detected once at startup). The Gateway declares `allowedListeners: {namespaces: {from: Same}}` whenever any overflow ListenerSet exists, or when `controller.gateway.allowListenerSets` is set. A ListenerSet that empties out is deleted rather than left as an empty resource, since the CRD requires at least one listener.

Listener placement is sticky: once a hostname (or a wildcard collapse target) is placed on the Gateway or a given ListenerSet, subsequent reconciliations keep it there as long as there is room, even as other hostnames come and go. A freshly collapsing or un-collapsing hostname prefers the placement of a related hostname it is joining or leaving, keeping locality across a collapse transition. When the ListenerSet API is unavailable, a hostname that does not fit in the Gateway's 63 HTTPS listeners is rejected with a field-level `Error` on every Ingress that declared it; every other hostname is served normally.

The bridge owns the managed Gateway specification. It refuses to adopt a pre-existing Gateway unless it already has:

```yaml
gateway.zyno.io/managed-by: ingress-nginx-gateway-bridge
```

Use route-only mode (`controller.gateway.manage=false`) when the platform owns all listeners independently.

When an Ingress backend is an `ExternalName` Service, NGF requires DNS resolver settings in a same-namespace `NginxProxy`. Set `controller.gateway.nginxProxyName` to make the managed Gateway reference that platform-owned resource. The bridge does not create it because resolver addresses are cluster-specific.

Gateway API `ReferenceGrant` can restrict the source namespace and kind but not a specific source object name. Consequently, each generated grant permits Gateways—and, whenever the `ListenerSet` CRD is installed (regardless of whether this Gateway currently has any overflow), any ListenerSet—in the configured Gateway namespace, not only bridge-managed ones, to reference that named TLS Secret. This is deliberately provisioned ahead of need, so a Secret's grant does not have to be recreated the moment its listener first overflows. Keep the Gateway namespace platform-controlled, and do not let a platform-owned ListenerSet there declare a hostname the bridge manages.

### Listener transitions

Moving a declared hostname between an exact listener and a wildcard collapse listener (or between the Gateway and an overflow ListenerSet) changes which parent its `HTTPRoute` must attach to. Affected Ingresses are re-pushed at high priority as soon as the new plan is known, but there is a brief window—until that Ingress reconciles—where the hostname's HTTPS listener does not yet match its route's parent reference. Enabling wildcard collapse on an existing installation triggers this transition once, for every hostname that was previously served by its own exact listener and is now covered by a wildcard.

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

NGF rejects a route-attached policy when another route has the same Gateway, hostname, port, and path but is not targeted by that same policy. The bridge consolidates a header canary into its corresponding primary Ingress's `HTTPRoute`, allowing one `ClientSettingsPolicy` and `ProxySettingsPolicy` to cover both rules. The consolidated route is owned by the primary Ingress; the canary's `IngressTranslation` records that delegation and follows the primary translation's readiness. Other overlapping route families use generated snippets for proxy settings, while `proxy-body-size` is rejected because a route-location snippet cannot raise the limit early enough in NGF's request dispatch.

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

Certificate grants also admit ListenerSets from the Gateway namespace whenever the `ListenerSet` CRD is installed (see above), independent of whether this Gateway currently has any overflow; any ListenerSet in that namespace can then attach to the Gateway and use those grants, so platform-owned ListenerSets there must not declare the HTTPS hostnames the bridge manages.

Wildcard collapse requires `list`/`watch` (and, by RBAC convention, `get`) on Secrets. Kubernetes RBAC has no way to scope that grant to `kubernetes.io/tls`-typed Secrets specifically—the chart's rule grants read access to every Secret in the cluster—so a field selector only limits what the controller's own cache retrieves and retains; it is not a permissions boundary. The API server still streams complete Secret objects to the controller process; a cache Transform discards all data, labels, annotations, and `managedFields` before the object is committed to the informer cache, retaining only a fingerprint and the certificate's wildcard SANs. No PEM, key, or certificate material is ever written back to a Kubernetes object or held beyond that in-memory cache entry. If the RBAC granting Secret access is removed while `--collapse-wildcard-certificates` stays enabled (or vice versa with the chart's conditional rule), the Secret informer fails to sync and the controller crash-loops on startup rather than running with a silently incomplete view; keep the flag and the chart's `collapseWildcardCertificates` value in agreement.
