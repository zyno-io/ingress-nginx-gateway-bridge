# ingress-nginx-gateway-bridge

`ingress-nginx-gateway-bridge` is a live compatibility controller for moving from the community
[ingress-nginx](https://github.com/kubernetes/ingress-nginx) controller to
[NGINX Gateway Fabric](https://github.com/nginx/nginx-gateway-fabric) without requiring every application or Helm chart to adopt Gateway API first.

The bridge continuously projects selected Kubernetes `Ingress` objects into `HTTPRoute`, `Gateway`, and NGINX Gateway Fabric policy/filter resources. The original Ingress remains the source of truth until the application is migrated to native Gateway API resources.

> [!CAUTION]
> This project is an implementation-specific migration bridge, not a new general-purpose Ingress implementation. Translation is strict by default: a route is removed when its ingress-nginx behavior cannot be reproduced faithfully.

## Why it exists

Many third-party Helm charts still emit only `Ingress`. NGINX Gateway Fabric intentionally implements Gateway API rather than the Ingress API. This bridge lets a platform hot-swap the data plane while applications migrate independently:

```text
Helm chart / application
          │
          ▼
       Ingress ──► ingress-nginx-gateway-bridge
                         │
                         ├── HTTPRoute
                         ├── ClientSettingsPolicy / ProxySettingsPolicy
                         ├── BackendTLSPolicy
                         ├── AuthenticationFilter / SnippetsFilter
                         └── Gateway listeners + ReferenceGrants
                                           │
                                           ▼
                              NGINX Gateway Fabric
```

## Hot-swap defaults

An IngressClass is not required. By default, the controller translates:

- Ingresses without a class
- Ingresses with `spec.ingressClassName: nginx`
- Ingresses with the legacy `kubernetes.io/ingress.class: nginx` annotation

Selection can be changed with Helm values or flags. `gateway.zyno.io/enabled: "true"` explicitly opts an Ingress in, while `gateway.zyno.io/ignore: "true"` opts it out. An optional `IngressClass` can be created for installations that prefer isolation.

## Safety model

- Unknown `nginx.ingress.kubernetes.io/*` annotations are fatal in strict mode.
- Per-Ingress generated objects use deterministic names, server-side apply, labels, and same-namespace owner references; shared Gateway and certificate-grant state is labeled separately.
- The controller refuses to adopt an existing object that is not already labeled as bridge-managed.
- Updates prune stale generated resources.
- Deletion is protected by a finalizer so managed Gateway listeners are removed.
- `IngressTranslation` exposes `Translated` and `Ready` conditions plus field-level issues, including rejected NGF policies and filters.
- Source-provided NGINX snippets are disabled by default.
- The shared Gateway is reconciled serially and once at startup, including when no Ingress is currently selected.

See [the compatibility matrix](docs/compatibility.md) for annotation-level behavior and known gaps.

## Prerequisites

- Kubernetes 1.31 or newer
- Gateway API 1.5 CRDs
- NGINX Gateway Fabric 2.6.x
- An NGF `GatewayClass` (the default expected name is `nginx`)
- NGF snippets enabled when using unverified HTTPS backends, external auth, capture-group rewrites, request-buffering overrides, or source snippets:

```yaml
nginxGateway:
  snippets:
    enable: true
```

## Install

```sh
helm upgrade --install ingress-nginx-gateway-bridge \
  oci://ghcr.io/zyno-io/charts/ingress-nginx-gateway-bridge \
  --namespace nginx-gateway \
  --create-namespace
```

For a side-by-side preflight, prevent the bridge from changing Ingress status—and therefore from influencing an Ingress-watching external-dns instance:

```sh
helm upgrade --install ingress-nginx-gateway-bridge \
  ./charts/ingress-nginx-gateway-bridge \
  --namespace nginx-gateway \
  --create-namespace \
  --set controller.updateIngressStatus=false
```

Inspect every translation before switching traffic:

```sh
kubectl get ingresstranslations.gateway.zyno.io -A
kubectl get ingresstranslations.gateway.zyno.io -A \
  -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,TRANSLATED:.status.conditions[0].status,READY:.status.conditions[1].status,ISSUES:.status.issues[*].message'
```

See [the hot-swap runbook](docs/hot-swap.md) before using the controller alongside ingress-nginx.

## Configuration

| Helm value | Default | Purpose |
|---|---:|---|
| `controller.gateway.manage` | `true` | Reconcile the shared Gateway and derive TLS listeners from Ingress TLS blocks |
| `controller.gateway.namespace` | Release namespace | Target Gateway namespace |
| `controller.gateway.name` | `ingress-nginx` | Target Gateway name |
| `controller.gateway.className` | `nginx` | GatewayClass for a managed Gateway |
| `controller.gateway.nginxProxyName` | empty | Optional same-namespace NGF `NginxProxy` parameters resource; required for `ExternalName` backends |
| `controller.watchIngressWithoutClass` | `true` | Include classless Ingresses |
| `controller.ingressClasses` | `[nginx]` | Additional selected Ingress class names |
| `controller.strict` | `true` | Reject unknown ingress-nginx annotations |
| `controller.allowSnippets` | `false` | Permit source-provided raw snippets |
| `controller.updateIngressStatus` | `true` | Mirror the Gateway address into Ingress status |
| `ingressClass.create` | `false` | Create the optional `ngf-compat` IngressClass |

## Development

Go 1.26.5 or newer is required. This minimum includes the standard-library fix for GO-2026-5856.

```sh
make test
make lint
make helm-lint
make docker-build IMG=ghcr.io/zyno-io/ingress-nginx-gateway-bridge:dev
```

## License

Apache-2.0.

NGINX is a trademark of F5, Inc. This community project is not affiliated with or endorsed by F5 or the NGINX Gateway Fabric maintainers.
