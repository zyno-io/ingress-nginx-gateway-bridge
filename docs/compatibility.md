# ingress-nginx annotation compatibility

The bridge is deliberately implementation-specific. This table describes the currently declared compatibility contract.

| ingress-nginx annotation | Translation | Status |
|---|---|---|
| `proxy-body-size` | NGF `ClientSettingsPolicy.spec.body.maxSize`; generated location snippet for overlapping route families | Supported |
| `proxy-connect-timeout` | NGF `ProxySettingsPolicy.spec.timeout.connect`; generated location snippet for overlapping route families | Supported |
| `proxy-read-timeout` | NGF `ProxySettingsPolicy.spec.timeout.read`; generated location snippet for overlapping route families | Supported |
| `proxy-send-timeout` | NGF `ProxySettingsPolicy.spec.timeout.send`; generated location snippet for overlapping route families | Supported |
| `proxy-buffering` | NGF `ProxySettingsPolicy.spec.buffering.disable`; generated location snippet for overlapping route families | Supported |
| `proxy-buffer-size` | NGF `ProxySettingsPolicy.spec.buffering.bufferSize`; generated location snippet for overlapping route families | Supported |
| `proxy-request-buffering` | Generated location-context `SnippetsFilter` | Supported; NGF snippets required |
| `enable-cors`, `cors-allow-origin`, `cors-allow-methods`, `cors-allow-headers`, `cors-expose-headers`, `cors-allow-credentials`, `cors-max-age` | Gateway API 1.5 `CORS` filter | Supported; NGF returns `200` for successful preflight where ingress-nginx returns `204` |
| `canary`, `canary-by-header`, `canary-by-header-value` | `HTTPRouteMatch.headers` | Supported as a complete header/value set |
| `rewrite-target` | `URLRewrite` for literal paths; generated rewrite snippet for capture groups | Supported; captures require NGF snippets |
| `ssl-redirect` | Separate HTTP `RequestRedirect` route | Supported |
| `upstream-vhost` | `RequestHeaderModifier` setting `Host` | Supported |
| `server-alias` | Additional hostname-specific HTTPRoutes | Supported; aliases not covered by TLS remain HTTP-only |
| `auth-type` set to `basic` and `auth-secret` | NGF `AuthenticationFilter` | Supported; NGF's default realm is `Authentication Required` when `auth-realm` is omitted |
| `auth-url` | Generated internal auth location and `auth_request` `SnippetsFilter` | Supported; NGF snippets required |
| `auth-response-headers` | Generated `auth_request_set` and upstream request headers | Supported with `auth-url` |
| `auth-signin` | Generated 401 error-page redirect | Supported with `auth-url`; ingress-nginx-only variables such as `$escaped_request_uri` are rejected, and the bridge does not append ingress-nginx's implicit `rd` query parameter |
| `auth-proxy-set-headers` | Watched ConfigMap data becomes request headers on the internal auth subrequest | Supported with `auth-url` |
| `auth-snippet` | Source snippet inside the generated internal auth location | Requires `--allow-snippets` |
| `configuration-snippet` | Source location snippet | Requires `--allow-snippets` |
| `server-snippet` | Source server snippet | Requires `--allow-snippets` |
| `proxy-http-version` | NGF's upstream HTTP/1.1 default | Supported when set to `1.1` |
| `backend-protocol` set to `HTTP` | Standard Service backend | Supported |
| `backend-protocol` set to `HTTPS` with `proxy-ssl-verify`, `proxy-ssl-server-name`, `proxy-ssl-name`, and `proxy-ssl-secret` | Gateway API `BackendTLSPolicy` | Supported when verification and SNI are on and the CA Secret is local |
| `backend-protocol` set to `HTTPS` without verified trust configuration | None | Blocked: unverified upstream TLS is intentionally unsupported |
| Other `nginx.ingress.kubernetes.io/*` annotations | None | Fatal in strict mode; warning otherwise |

## Known semantic boundaries

- Header-based canaries rely on Gateway API match precedence. Weight- and cookie-based canaries are not yet implemented.
- NGF snippets must be enabled when overlapping route families use client or proxy setting annotations. This avoids NGF's route-attached-policy `TargetConflict` rule while retaining the more-specific header match.
- Source snippets are intentionally not parsed or rewritten. They are copied only after the operator enables the privileged compatibility mode.
- `auth-signin` values must use variables available in standard NGINX/NGF. Ingress-nginx's Lua-provided `$escaped_request_uri` is rejected because substituting `$request_uri` is not equivalent when the value is nested in a redirect query parameter.
- The supplied `auth-signin` URL is emitted as-is. ingress-nginx implicitly appends an escaped `rd` parameter; NGF lacks ingress-nginx's URI-escaping module, so applications that need a return target should include their own supported redirect parameter in `auth-signin` (the audited Vouch routes already use `url=`).
- Generated regex rewrites use NGF's regular-expression HTTPRoute matching plus a location snippet.
- Backend HTTPS requires ingress-nginx's verified trust annotations; the referenced Secret must contain `ca.crt` and reside in the Ingress namespace. The generated `BackendTLSPolicy` targets the Service, so isolate a Service when different ports require different TLS settings.
- Non-Service resource backends are rejected.
- More than 16 paths for one hostname is currently rejected instead of being split across routes.
- More than 63 frontend TLS hostnames requires splitting traffic across Gateways or future ListenerSet support.

## Verified kube-api edge profile

The repository's kube-api edge combination is fully declared: `auth-proxy-set-headers`, `auth-url`, verified `HTTPS` backend protocol, body size `0`, response/request buffering controls, connect/read/send timeouts, HTTP/1.1, CA Secret, SNI name, SNI/verification switches, and `upstream-vhost`. It produces an internal external-auth `SnippetsFilter`, watched ConfigMap headers (including an explicitly empty `Cookie` header), `ClientSettingsPolicy`, `ProxySettingsPolicy`, `BackendTLSPolicy`, Host request-header modification, and the application `HTTPRoute`.

That manifest's `kubernetes-api` backend is an `ExternalName` Service, which additionally requires `controller.gateway.nginxProxyName` to reference a platform-owned NGF DNS resolver. Its oauth2-proxy NetworkPolicy must admit the NGF Gateway namespace during preflight; neither requirement is expressible in an Ingress annotation.
