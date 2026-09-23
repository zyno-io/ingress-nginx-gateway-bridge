// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// CertificateInfo is the durable projection of a TLS Secret's leaf
// certificate used to plan wildcard listener collapse. It intentionally
// retains no certificate material.
type CertificateInfo struct {
	// WildcardSANs holds the certificate's wildcard subject alternative
	// names, lower-cased as "*.suffix", sorted, and deduplicated.
	WildcardSANs []string `json:"wildcardSANs,omitempty"`
	// Fingerprint is the hex-encoded SHA-256 digest of the certificate's DER chain.
	Fingerprint string `json:"fingerprint"`
}

// ParseCertificateInfo validates a TLS Secret's key material the same way
// NGF does and, on success, extracts the leaf certificate's wildcard SANs
// and a stable fingerprint of its chain. It reports false for any Secret
// that NGF itself would reject, since such a Secret cannot back a listener.
func ParseCertificateInfo(data map[string][]byte) (CertificateInfo, bool) {
	pair, err := tls.X509KeyPair(data["tls.crt"], data["tls.key"])
	if err != nil || len(pair.Certificate) == 0 {
		return CertificateInfo{}, false
	}
	if ca, present := data["ca.crt"]; present && !validCABundle(ca) {
		return CertificateInfo{}, false
	}

	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return CertificateInfo{}, false
		}
	}

	hasher := sha256.New()
	var lengthPrefix [4]byte
	for _, der := range pair.Certificate {
		binary.BigEndian.PutUint32(lengthPrefix[:], uint32(len(der)))
		hasher.Write(lengthPrefix[:])
		hasher.Write(der)
	}

	return CertificateInfo{
		WildcardSANs: wildcardSANs(leaf),
		Fingerprint:  fmt.Sprintf("%x", hasher.Sum(nil)),
	}, true
}

// validCABundle mirrors NGF's shared/secrets.ValidateCA: the data is
// base64-decoded when possible (falling back to the raw bytes), and the
// first PEM block must be a parseable CERTIFICATE. An empty or malformed
// ca.crt is invalid, matching NGF's rejection of such Secrets.
func validCABundle(caData []byte) bool {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(caData)))
	n, err := base64.StdEncoding.Decode(decoded, caData)
	if err != nil {
		decoded = caData
	} else {
		decoded = decoded[:n]
	}
	block, _ := pem.Decode(decoded)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	_, err = x509.ParseCertificate(block.Bytes)
	return err == nil
}

// wildcardSANs extracts the leaf certificate's single-label wildcard DNS
// SANs, e.g. "*.example.com". Multi-level wildcards, bare wildcards, and
// non-wildcard SANs are excluded; collapse only ever targets one-label wildcards.
func wildcardSANs(leaf *x509.Certificate) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, name := range leaf.DNSNames {
		name = strings.ToLower(strings.TrimSpace(name))
		name = strings.TrimSuffix(name, ".")
		if !strings.HasPrefix(name, "*.") {
			continue
		}
		suffix := name[2:]
		if suffix == "" || strings.Contains(suffix, "*") || strings.HasPrefix(suffix, ".") || strings.HasSuffix(suffix, ".") {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// coveringWildcard returns the wildcard SAN in info that covers host, or ""
// if host is itself a wildcard, has no parent label, or is not covered.
// Coverage requires exactly one extra label: "a.b.s24.dev" is covered by
// "*.b.s24.dev" but not by "*.s24.dev".
func coveringWildcard(host string, info CertificateInfo) string {
	if strings.HasPrefix(host, "*.") {
		return ""
	}
	dot := strings.IndexByte(host, '.')
	if dot <= 0 || dot == len(host)-1 {
		return ""
	}
	candidate := "*" + host[dot:]
	if slices.Contains(info.WildcardSANs, candidate) {
		return candidate
	}
	return ""
}
