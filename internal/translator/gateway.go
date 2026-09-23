// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	ngfv1alpha2 "github.com/nginx/nginx-gateway-fabric/v2/apis/v1alpha2"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/zyno-io/ingress-nginx-gateway-bridge/internal/naming"
)

// Gateway API caps a Gateway (and, separately, each ListenerSet) at 64
// listeners. The managed Gateway reserves one slot for its HTTP listener.
const (
	gatewayHTTPSCapacity = 63
	listenerSetCapacity  = 64
)

// ManagedGatewayOptions controls the shared Gateway generated in hot-swap mode.
type ManagedGatewayOptions struct {
	Namespace         string
	Name              string
	ClassName         string
	NginxProxyName    string
	AllowListenerSets bool
	HTTPSectionName   string
	HTTPSSectionName  string
	// ListenerSetOverflow reports whether the ListenerSet API is installed,
	// allowing overflow HTTPS listeners beyond the Gateway's own capacity.
	ListenerSetOverflow bool
	// Certificates carries parsed leaf-certificate info for every TLS Secret
	// referenced by a selected Ingress. A nil map disables wildcard collapse
	// entirely; a missing entry for a referenced Secret means that Secret's
	// certificate is not collapsible (invalid, unparsable, or not yet read).
	Certificates map[types.NamespacedName]CertificateInfo
	// CurrentPlacements is the previous plan's listener placement, keyed by
	// listener hostname. It is used to keep listener placement sticky across
	// reconciliations.
	CurrentPlacements map[string]ListenerPlacement
}

// ListenerPlacement records which parent serves a listener hostname.
type ListenerPlacement struct {
	// ListenerSet is 0 for the Gateway itself, or the 1-based index of a
	// bridge-managed overflow ListenerSet.
	ListenerSet int
	Secret      types.NamespacedName
}

// GatewayPlan is the cluster-wide listener projection of all selected Ingresses.
type GatewayPlan struct {
	Gateway gatewayv1.Gateway
	// ListenerSets holds bridge-managed overflow ListenerSets in ascending
	// index order. It is empty when every HTTPS listener fits on the Gateway.
	ListenerSets    []gatewayv1.ListenerSet
	ReferenceGrants []gatewayv1.ReferenceGrant
	// TLSHosts is the set of declared TLS hostnames only; a wildcard
	// collapse target that no Ingress declared directly is never a member.
	TLSHosts map[string]struct{}
	// TLSSections maps every declared TLS hostname to the listener that
	// actually serves it, which may be a wildcard listener covering it.
	TLSSections map[string]ListenerRef
	// Placements is keyed by listener hostname (the wildcard target for a
	// collapsed listener, or the hostname itself otherwise).
	Placements map[string]ListenerPlacement
	Issues     map[types.NamespacedName][]Issue
}

type certificateSource struct {
	namespace string
	secret    string
	source    types.NamespacedName
}

// listenerClaim is one declared TLS hostname competing for a listener,
// either its own exact listener or a shared wildcard listener.
type listenerClaim struct {
	host   string
	secret types.NamespacedName
	// pinned is true when host itself is the wildcard hostname, i.e. an
	// Ingress declared "*.example.com" directly rather than a covered host.
	pinned bool
}

// projectedListener is one HTTPS listener the managed Gateway or one of its
// ListenerSets will emit, before placement onto a specific parent.
type projectedListener struct {
	hostname string
	secret   types.NamespacedName
	// hosts are the declared TLS hostnames this listener serves. It is a
	// single element unless the listener is a wildcard collapse winner.
	hosts []string
}

// ManagedListenerSetName returns the deterministic name of the bridge-managed
// overflow ListenerSet at the given 1-based index.
func ManagedListenerSetName(gatewayName string, index int) string {
	return naming.DNSLabel(gatewayName, strconv.Itoa(index))
}

// BuildManagedGateway projects every selected Ingress's TLS declarations onto
// one shared HTTP listener, one HTTPS listener per exact or collapsed
// wildcard hostname, and, when the hostname count exceeds the Gateway's own
// capacity, bridge-managed overflow ListenerSets.
//
// Invariants preserved throughout: every declared hostname is served by
// exactly one listener; every emitted listener belongs to exactly one parent
// (the Gateway or a single ListenerSet), so hostnames never duplicate across
// parents; and an empty ListenerSet is never emitted, since the CRD requires
// at least one listener and the controller prunes ListenerSets that are no
// longer desired.
func BuildManagedGateway(ingresses []networkingv1.Ingress, options ManagedGatewayOptions) GatewayPlan {
	fromAll := gatewayv1.NamespacesFromAll
	allowedRoutes := &gatewayv1.AllowedRoutes{Namespaces: &gatewayv1.RouteNamespaces{From: &fromAll}}
	plan := GatewayPlan{
		TLSHosts:    make(map[string]struct{}),
		TLSSections: make(map[string]ListenerRef),
		Placements:  make(map[string]ListenerPlacement),
		Issues:      make(map[types.NamespacedName][]Issue),
	}
	plan.Gateway = gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: GatewayKind},
		ObjectMeta: metav1.ObjectMeta{
			Name:      options.Name,
			Namespace: options.Namespace,
			Labels: map[string]string{
				ManagedByLabel: ControllerName,
				GatewayLabel:   GatewayLabelValue(options.Namespace, options.Name),
			},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(options.ClassName),
			Listeners: []gatewayv1.Listener{{
				Name:          gatewayv1.SectionName(options.HTTPSectionName),
				Port:          80,
				Protocol:      gatewayv1.HTTPProtocolType,
				AllowedRoutes: allowedRoutes,
			}},
		},
	}
	if options.NginxProxyName != "" {
		plan.Gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
			ParametersRef: &gatewayv1.LocalParametersReference{
				Group: gatewayv1.Group(ngfv1alpha2.GroupName),
				Kind:  "NginxProxy",
				Name:  options.NginxProxyName,
			},
		}
	}

	// Collect declared TLS hosts in deterministic (namespace, name) order so
	// conflicting Ingresses always agree on which Secret "wins" first-seen.
	sorted := append([]networkingv1.Ingress(nil), ingresses...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Namespace != sorted[j].Namespace {
			return sorted[i].Namespace < sorted[j].Namespace
		}
		return sorted[i].Name < sorted[j].Name
	})

	certificates := make(map[string]certificateSource)
	declaredBy := make(map[string]map[types.NamespacedName]struct{})
	for idx := range sorted {
		ing := &sorted[idx]
		if !ing.DeletionTimestamp.IsZero() {
			continue
		}
		source := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		for _, tls := range ing.Spec.TLS {
			secret := strings.TrimSpace(tls.SecretName)
			if secret == "" {
				plan.Issues[source] = append(plan.Issues[source], Issue{
					Severity: SeverityError,
					Field:    "spec.tls.secretName",
					Message:  "managed listeners require a TLS Secret name",
				})
				continue
			}
			hosts := effectiveTLSHosts(ing, tls)
			if len(hosts) == 0 {
				plan.Issues[source] = append(plan.Issues[source], Issue{
					Severity: SeverityError,
					Field:    "spec.tls.hosts",
					Message:  "TLS entry has no hosts and the Ingress has no named rules from which to infer them",
				})
				continue
			}
			for _, rawHost := range hosts {
				host := strings.ToLower(strings.TrimSpace(rawHost))
				if host == "" {
					plan.Issues[source] = append(plan.Issues[source], Issue{
						Severity: SeverityError,
						Field:    "spec.tls.hosts",
						Message:  "managed listeners do not support an empty TLS hostname",
					})
					continue
				}
				candidate := certificateSource{namespace: ing.Namespace, secret: secret, source: source}
				if declaredBy[host] == nil {
					declaredBy[host] = make(map[types.NamespacedName]struct{})
				}
				declaredBy[host][source] = struct{}{}
				if existing, exists := certificates[host]; exists &&
					(existing.namespace != candidate.namespace || existing.secret != candidate.secret) {
					message := fmt.Sprintf(
						"TLS hostname %q conflicts with Secret %s/%s selected by Ingress %s/%s",
						host, existing.namespace, existing.secret, existing.source.Namespace, existing.source.Name,
					)
					plan.Issues[source] = append(plan.Issues[source], Issue{Severity: SeverityError, Field: "spec.tls", Message: message})
					plan.Issues[existing.source] = append(plan.Issues[existing.source], Issue{Severity: SeverityError, Field: "spec.tls", Message: message})
					continue
				}
				plan.TLSHosts[host] = struct{}{}
				certificates[host] = candidate
			}
		}
	}

	// Group every declared host under its collapsed wildcard target, when
	// its certificate carries a matching one-label wildcard SAN.
	hosts := make([]string, 0, len(certificates))
	for host := range certificates {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	groups := make(map[string][]listenerClaim)
	var targets []string
	for _, host := range hosts {
		owner := certificates[host]
		secret := types.NamespacedName{Namespace: owner.namespace, Name: owner.secret}
		pinned := strings.HasPrefix(host, "*.")
		target := host
		if !pinned && options.Certificates != nil {
			if info, ok := options.Certificates[secret]; ok {
				if w := coveringWildcard(host, info); w != "" {
					target = w
				}
			}
		}
		if _, exists := groups[target]; !exists {
			targets = append(targets, target)
		}
		groups[target] = append(groups[target], listenerClaim{host: host, secret: secret, pinned: pinned})
	}
	sort.Strings(targets)

	// Resolve each group into one winning listener, plus any group members
	// that fall back to their own exact listener.
	var projected []projectedListener
	for _, target := range targets {
		claims := groups[target]
		if !strings.HasPrefix(target, "*.") {
			c := claims[0]
			projected = append(projected, projectedListener{hostname: target, secret: c.secret, hosts: []string{c.host}})
			continue
		}
		winner, fallbacks := resolveWildcardGroup(target, claims, options)
		projected = append(projected, winner)
		projected = append(projected, fallbacks...)
	}

	// Place every listener onto the Gateway or, once it is full, an overflow
	// ListenerSet, sticking to each listener's previous placement.
	placed, unplaced := placeListeners(projected, options)

	// Hosts that could not be placed are reported on every Ingress that
	// declared them; the rest of the managed Gateway is unaffected.
	for _, l := range unplaced {
		for _, host := range l.hosts {
			for _, source := range sortedNamespacedNames(declaredBy[host]) {
				plan.Issues[source] = append(plan.Issues[source], Issue{
					Severity: SeverityError,
					Field:    "spec.tls",
					Message: fmt.Sprintf(
						"TLS hostname %q cannot be served: the managed Gateway already has 63 HTTPS listeners and the ListenerSet API is unavailable",
						host,
					),
				})
			}
		}
	}

	// Emit placed listeners in hostname order, splitting them across the
	// Gateway and any bridge-managed ListenerSets they were placed into.
	byHostname := make(map[string]projectedListener, len(projected))
	for _, l := range projected {
		byHostname[l.hostname] = l
	}
	placedHostnames := make([]string, 0, len(placed))
	for hostname := range placed {
		placedHostnames = append(placedHostnames, hostname)
	}
	sort.Strings(placedHostnames)

	setEntries := make(map[int][]gatewayv1.ListenerEntry)
	maxIndex := 0
	for _, hostname := range placedHostnames {
		l := byHostname[hostname]
		idx := placed[hostname]
		section := naming.DNSLabel(options.HTTPSSectionName, hostname)
		listener := httpsListener(hostname, l.secret, section, allowedRoutes)
		if idx == 0 {
			plan.Gateway.Spec.Listeners = append(plan.Gateway.Spec.Listeners, listener)
		} else {
			setEntries[idx] = append(setEntries[idx], gatewayv1.ListenerEntry(listener))
			if idx > maxIndex {
				maxIndex = idx
			}
		}
		ref := listenerRef(hostname, idx, options)
		for _, h := range l.hosts {
			plan.TLSSections[h] = ref
		}
		plan.Placements[hostname] = ListenerPlacement{ListenerSet: idx, Secret: l.secret}
	}
	for idx := 1; idx <= maxIndex; idx++ {
		entries, ok := setEntries[idx]
		if !ok {
			// A previously used index has emptied out; leave it unemitted so
			// the controller prunes it instead of applying an empty set.
			continue
		}
		plan.ListenerSets = append(plan.ListenerSets, managedListenerSet(options, idx, entries))
	}
	if options.AllowListenerSets || len(plan.ListenerSets) > 0 {
		fromSame := gatewayv1.NamespacesFromSame
		plan.Gateway.Spec.AllowedListeners = &gatewayv1.AllowedListeners{
			Namespaces: &gatewayv1.ListenerNamespaces{From: &fromSame},
		}
	}

	// Grant cross-namespace access only for Secrets an emitted listener
	// actually references, never every Secret an Ingress merely named.
	grantSecrets := make(map[types.NamespacedName]struct{})
	for _, placement := range plan.Placements {
		if placement.Secret.Namespace != options.Namespace {
			grantSecrets[placement.Secret] = struct{}{}
		}
	}
	for _, secret := range sortedNamespacedNames(grantSecrets) {
		plan.ReferenceGrants = append(plan.ReferenceGrants, certificateReferenceGrant(secret.Namespace, secret.Name, options))
	}

	return plan
}

// resolveWildcardGroup picks the winning certificate class for a wildcard
// collapse target and returns its listener plus one exact fallback listener
// for every claim outside the winning class.
func resolveWildcardGroup(
	target string,
	claims []listenerClaim,
	options ManagedGatewayOptions,
) (projectedListener, []projectedListener) {
	classOf := func(secret types.NamespacedName) string {
		if options.Certificates != nil {
			if info, ok := options.Certificates[secret]; ok && info.Fingerprint != "" {
				return "fp:" + info.Fingerprint
			}
		}
		return "secret:" + secret.String()
	}

	type wildcardClass struct {
		claims  []listenerClaim
		secrets []types.NamespacedName
		hosts   []string
		pinned  bool
	}
	classesByKey := make(map[string]*wildcardClass)
	var order []string
	for _, c := range claims {
		key := classOf(c.secret)
		wc, exists := classesByKey[key]
		if !exists {
			wc = &wildcardClass{}
			classesByKey[key] = wc
			order = append(order, key)
		}
		wc.claims = append(wc.claims, c)
		if c.pinned {
			wc.pinned = true
		}
	}
	for _, wc := range classesByKey {
		secretSet := make(map[types.NamespacedName]struct{}, len(wc.claims))
		hostSet := make(map[string]struct{}, len(wc.claims))
		for _, c := range wc.claims {
			secretSet[c.secret] = struct{}{}
			hostSet[c.host] = struct{}{}
		}
		wc.secrets = sortedNamespacedNames(secretSet)
		wc.hosts = sortedStrings(hostSet)
	}

	// A literal wildcard TLS declaration always wins its class outright.
	winnerKey := ""
	for _, key := range order {
		if classesByKey[key].pinned {
			winnerKey = key
			break
		}
	}
	if winnerKey == "" {
		type score struct {
			key         string
			churn       int
			hosts       int
			firstSecret string
		}
		scores := make([]score, 0, len(order))
		for _, key := range order {
			wc := classesByKey[key]
			inClass := make(map[string]struct{}, len(wc.claims))
			for _, c := range wc.claims {
				inClass[c.host] = struct{}{}
			}
			churn := 0
			for _, c := range claims {
				prev, havePrev := "", false
				switch {
				case pointsAt(options.CurrentPlacements, c.host):
					prev, havePrev = c.host, true
				case pointsAt(options.CurrentPlacements, target):
					prev, havePrev = target, true
				}
				if !havePrev {
					continue
				}
				wanted := c.host
				if _, inC := inClass[c.host]; inC {
					wanted = target
				}
				if prev != wanted {
					churn++
				}
			}
			scores = append(scores, score{key: key, churn: churn, hosts: len(wc.hosts), firstSecret: wc.secrets[0].String()})
		}
		sort.Slice(scores, func(i, j int) bool {
			if scores[i].churn != scores[j].churn {
				return scores[i].churn < scores[j].churn
			}
			if scores[i].hosts != scores[j].hosts {
				return scores[i].hosts > scores[j].hosts
			}
			return scores[i].firstSecret < scores[j].firstSecret
		})
		winnerKey = scores[0].key
	}

	winner := classesByKey[winnerKey]
	canonical := winner.secrets[0]
	if previous, ok := options.CurrentPlacements[target]; ok {
		for _, s := range winner.secrets {
			if s == previous.Secret {
				canonical = previous.Secret
				break
			}
		}
	}
	winnerListener := projectedListener{hostname: target, secret: canonical, hosts: winner.hosts}

	var fallbacks []projectedListener
	for _, key := range order {
		if key == winnerKey {
			continue
		}
		for _, c := range classesByKey[key].claims {
			fallbacks = append(fallbacks, projectedListener{hostname: c.host, secret: c.secret, hosts: []string{c.host}})
		}
	}
	sort.Slice(fallbacks, func(i, j int) bool { return fallbacks[i].hostname < fallbacks[j].hostname })
	return winnerListener, fallbacks
}

func pointsAt(placements map[string]ListenerPlacement, hostname string) bool {
	_, ok := placements[hostname]
	return ok
}

// placeListeners assigns every projected listener to the Gateway (index 0)
// or an overflow ListenerSet, preferring each listener's previous placement,
// then a placement inherited from a related hostname, before falling back to
// the first parent with room.
func placeListeners(listeners []projectedListener, options ManagedGatewayOptions) (map[string]int, []projectedListener) {
	sorted := append([]projectedListener(nil), listeners...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].hostname < sorted[j].hostname })

	counts := make(map[int]int)
	placed := make(map[string]int, len(sorted))
	capacity := func(idx int) int {
		if idx == 0 {
			return gatewayHTTPSCapacity
		}
		return listenerSetCapacity
	}
	usable := func(idx int) bool {
		return idx == 0 || options.ListenerSetOverflow
	}
	tryPlace := func(l projectedListener, idx int) bool {
		if !usable(idx) || counts[idx] >= capacity(idx) {
			return false
		}
		placed[l.hostname] = idx
		counts[idx]++
		return true
	}

	var pass2 []projectedListener
	for _, l := range sorted {
		if prev, ok := options.CurrentPlacements[l.hostname]; ok && tryPlace(l, prev.ListenerSet) {
			continue
		}
		pass2 = append(pass2, l)
	}

	var pass3 []projectedListener
	for _, l := range pass2 {
		if idx, ok := inheritedPlacement(l, options.CurrentPlacements); ok && tryPlace(l, idx) {
			continue
		}
		pass3 = append(pass3, l)
	}

	var unplaced []projectedListener
	for _, l := range pass3 {
		if tryPlace(l, 0) {
			continue
		}
		if !options.ListenerSetOverflow {
			unplaced = append(unplaced, l)
			continue
		}
		for idx := 1; ; idx++ {
			if tryPlace(l, idx) {
				break
			}
		}
	}
	return placed, unplaced
}

// inheritedPlacement finds a placement to reuse for a listener that has
// never itself been placed, based on a related hostname that has been: for a
// wildcard listener, one of the hosts it now serves; for an exact listener,
// the wildcard it would collapse into.
func inheritedPlacement(l projectedListener, current map[string]ListenerPlacement) (int, bool) {
	if strings.HasPrefix(l.hostname, "*.") {
		members := sortedStrings(toSet(l.hosts))
		for _, member := range members {
			if member == l.hostname {
				continue
			}
			if placement, ok := current[member]; ok {
				return placement.ListenerSet, true
			}
		}
		return 0, false
	}
	dot := strings.IndexByte(l.hostname, '.')
	if dot <= 0 || dot == len(l.hostname)-1 {
		return 0, false
	}
	candidate := "*" + l.hostname[dot:]
	if placement, ok := current[candidate]; ok {
		return placement.ListenerSet, true
	}
	return 0, false
}

func httpsListener(hostname string, secret types.NamespacedName, sectionName string, allowedRoutes *gatewayv1.AllowedRoutes) gatewayv1.Listener {
	mode := gatewayv1.TLSModeTerminate
	secretNamespace := gatewayv1.Namespace(secret.Namespace)
	listenerHostname := gatewayv1.Hostname(hostname)
	return gatewayv1.Listener{
		Name:     gatewayv1.SectionName(sectionName),
		Hostname: &listenerHostname,
		Port:     443,
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.ListenerTLSConfig{
			Mode: &mode,
			CertificateRefs: []gatewayv1.SecretObjectReference{{
				Name: gatewayv1.ObjectName(secret.Name), Namespace: &secretNamespace,
			}},
		},
		AllowedRoutes: allowedRoutes,
	}
}

func managedListenerSet(options ManagedGatewayOptions, index int, entries []gatewayv1.ListenerEntry) gatewayv1.ListenerSet {
	return gatewayv1.ListenerSet{
		TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: ListenerSetKind},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ManagedListenerSetName(options.Name, index),
			Namespace: options.Namespace,
			Labels: map[string]string{
				ManagedByLabel:        ControllerName,
				GatewayLabel:          GatewayLabelValue(options.Namespace, options.Name),
				ListenerSetIndexLabel: strconv.Itoa(index),
			},
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Group: ptr(gatewayv1.Group(gatewayv1.GroupVersion.Group)),
				Kind:  ptr(gatewayv1.Kind(GatewayKind)),
				Name:  gatewayv1.ObjectName(options.Name),
			},
			Listeners: entries,
		},
	}
}

// listenerRef builds the ListenerRef for the listener serving hostname at
// the given placement index. Section names are deterministic so callers that
// only know the hostname and index can reproduce the same reference.
func listenerRef(hostname string, index int, options ManagedGatewayOptions) ListenerRef {
	section := naming.DNSLabel(options.HTTPSSectionName, hostname)
	if index == 0 {
		return ListenerRef{Kind: GatewayKind, Name: options.Name, SectionName: section}
	}
	return ListenerRef{Kind: ListenerSetKind, Name: ManagedListenerSetName(options.Name, index), SectionName: section}
}

// listenerRefFor resolves the listener currently serving a declared
// hostname: its own placement if present, otherwise its wildcard parent's.
func listenerRefFor(host string, placements map[string]ListenerPlacement, options ManagedGatewayOptions) (ListenerRef, bool) {
	if placement, ok := placements[host]; ok {
		return listenerRef(host, placement.ListenerSet, options), true
	}
	if strings.HasPrefix(host, "*.") {
		return ListenerRef{}, false
	}
	dot := strings.IndexByte(host, '.')
	if dot <= 0 || dot == len(host)-1 {
		return ListenerRef{}, false
	}
	candidate := "*" + host[dot:]
	if placement, ok := placements[candidate]; ok {
		return listenerRef(candidate, placement.ListenerSet, options), true
	}
	return ListenerRef{}, false
}

// ChangedTLSHosts reports every declared TLS hostname whose serving listener
// differs between the previous and the newly built plan. The controller uses
// this to re-push only the Ingresses whose routes must move parents.
func ChangedTLSHosts(previous map[string]ListenerPlacement, plan GatewayPlan, options ManagedGatewayOptions) map[string]struct{} {
	changed := make(map[string]struct{})
	for host, newRef := range plan.TLSSections {
		oldRef, ok := listenerRefFor(host, previous, options)
		if !ok || oldRef != newRef {
			changed[host] = struct{}{}
		}
	}
	return changed
}

func sortedNamespacedNames(set map[types.NamespacedName]struct{}) []types.NamespacedName {
	result := make([]types.NamespacedName, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}

func sortedStrings(set map[string]struct{}) []string {
	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}

// effectiveTLSHosts reproduces ingress-nginx's behavior for a TLS entry with
// an omitted hosts list by applying that entry to every named rule on the same
// Ingress. Hostless/default-backend TLS cannot be projected safely onto the
// shared hostname listener.
func effectiveTLSHosts(ing *networkingv1.Ingress, tls networkingv1.IngressTLS) []string {
	if len(tls.Hosts) > 0 {
		result := make([]string, 0, len(tls.Hosts))
		for _, raw := range tls.Hosts {
			if host := strings.ToLower(strings.TrimSpace(raw)); host != "" {
				result = append(result, host)
			}
		}
		return result
	}

	seen := make(map[string]struct{})
	result := make([]string, 0, len(ing.Spec.Rules))
	for _, rule := range ing.Spec.Rules {
		host := strings.ToLower(strings.TrimSpace(rule.Host))
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		result = append(result, host)
	}
	return result
}

func certificateReferenceGrant(namespace, secret string, options ManagedGatewayOptions) gatewayv1.ReferenceGrant {
	from := []gatewayv1.ReferenceGrantFrom{{
		Group:     gatewayv1.Group(gatewayv1.GroupVersion.Group),
		Kind:      GatewayKind,
		Namespace: gatewayv1.Namespace(options.Namespace),
	}}
	if options.ListenerSetOverflow {
		from = append(from, gatewayv1.ReferenceGrantFrom{
			Group:     gatewayv1.Group(gatewayv1.GroupVersion.Group),
			Kind:      ListenerSetKind,
			Namespace: gatewayv1.Namespace(options.Namespace),
		})
	}
	return gatewayv1.ReferenceGrant{
		TypeMeta: metav1.TypeMeta{APIVersion: gatewayv1.GroupVersion.String(), Kind: "ReferenceGrant"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      naming.DNSLabel(options.Name, secret, "gateway-cert"),
			Namespace: namespace,
			Labels: map[string]string{
				ManagedByLabel: ControllerName,
				GatewayLabel:   GatewayLabelValue(options.Namespace, options.Name),
			},
		},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: from,
			To: []gatewayv1.ReferenceGrantTo{{
				Group: "", Kind: "Secret", Name: ptr(gatewayv1.ObjectName(secret)),
			}},
		},
	}
}
