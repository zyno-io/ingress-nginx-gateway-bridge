// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

const annotationPrefix = "nginx.ingress.kubernetes.io/"

const (
	annProxyBodySize         = annotationPrefix + "proxy-body-size"
	annProxyReadTimeout      = annotationPrefix + "proxy-read-timeout"
	annProxySendTimeout      = annotationPrefix + "proxy-send-timeout"
	annProxyConnectTimeout   = annotationPrefix + "proxy-connect-timeout"
	annProxyBuffering        = annotationPrefix + "proxy-buffering"
	annProxyBufferSize       = annotationPrefix + "proxy-buffer-size"
	annProxyRequestBuffering = annotationPrefix + "proxy-request-buffering"
	annProxyHTTPVersion      = annotationPrefix + "proxy-http-version"
	annProxySSLName          = annotationPrefix + "proxy-ssl-name"
	annProxySSLSecret        = annotationPrefix + "proxy-ssl-secret"
	annProxySSLServerName    = annotationPrefix + "proxy-ssl-server-name"
	annProxySSLVerify        = annotationPrefix + "proxy-ssl-verify"
	annEnableCORS            = annotationPrefix + "enable-cors"
	annCORSAllowOrigin       = annotationPrefix + "cors-allow-origin"
	annCORSAllowMethods      = annotationPrefix + "cors-allow-methods"
	annCORSAllowHeaders      = annotationPrefix + "cors-allow-headers"
	annCORSExposeHeaders     = annotationPrefix + "cors-expose-headers"
	annCORSAllowCredentials  = annotationPrefix + "cors-allow-credentials"
	annCORSMaxAge            = annotationPrefix + "cors-max-age"
	annCanary                = annotationPrefix + "canary"
	annCanaryByHeader        = annotationPrefix + "canary-by-header"
	annCanaryByHeaderValue   = annotationPrefix + "canary-by-header-value"
	annRewriteTarget         = annotationPrefix + "rewrite-target"
	annSSLRedirect           = annotationPrefix + "ssl-redirect"
	annAuthURL               = annotationPrefix + "auth-url"
	annAuthMethod            = annotationPrefix + "auth-method"
	annAuthResponseHeaders   = annotationPrefix + "auth-response-headers"
	annAuthRequestRedirect   = annotationPrefix + "auth-request-redirect"
	annAuthSignin            = annotationPrefix + "auth-signin"
	annAuthSnippet           = annotationPrefix + "auth-snippet"
	annAuthType              = annotationPrefix + "auth-type"
	annAuthSecret            = annotationPrefix + "auth-secret"
	annAuthRealm             = annotationPrefix + "auth-realm"
	annAuthProxySetHeaders   = annotationPrefix + "auth-proxy-set-headers"
	annServerAlias           = annotationPrefix + "server-alias"
	annConfigurationSnippet  = annotationPrefix + "configuration-snippet"
	annServerSnippet         = annotationPrefix + "server-snippet"
	annUpstreamVHost         = annotationPrefix + "upstream-vhost"
	annBackendProtocol       = annotationPrefix + "backend-protocol"
	annUseRegex              = annotationPrefix + "use-regex"
)

var knownAnnotations = map[string]struct{}{
	annProxyBodySize: {}, annProxyReadTimeout: {}, annProxySendTimeout: {},
	annProxyConnectTimeout: {}, annProxyBuffering: {}, annProxyBufferSize: {},
	annProxyRequestBuffering: {}, annEnableCORS: {}, annCORSAllowOrigin: {},
	annProxyHTTPVersion: {}, annProxySSLName: {}, annProxySSLSecret: {},
	annProxySSLServerName: {}, annProxySSLVerify: {},
	annCORSAllowMethods: {}, annCORSAllowHeaders: {}, annCORSExposeHeaders: {},
	annCORSAllowCredentials: {}, annCORSMaxAge: {}, annCanary: {},
	annCanaryByHeader: {}, annCanaryByHeaderValue: {}, annRewriteTarget: {},
	annSSLRedirect: {}, annAuthURL: {}, annAuthMethod: {}, annAuthResponseHeaders: {},
	annAuthRequestRedirect: {}, annAuthSignin: {}, annAuthSnippet: {}, annAuthType: {},
	annAuthSecret: {}, annAuthRealm: {}, annAuthProxySetHeaders: {},
	annServerAlias: {}, annConfigurationSnippet: {}, annServerSnippet: {},
	annUpstreamVHost: {}, annBackendProtocol: {}, annUseRegex: {},
}
