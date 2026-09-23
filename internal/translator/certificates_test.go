// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package translator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// generateTestCertificate creates a self-signed ECDSA certificate for
// dnsNames and returns its PEM-encoded certificate and key, matching what a
// kubernetes.io/tls Secret would carry.
func generateTestCertificate(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestParseCertificateInfoExtractsSortedLowercaseSANs(t *testing.T) {
	cert, key := generateTestCertificate(t, "*.S24.dev", "*.b.s24.dev", "example.com", "*.a.s24.dev")
	info, ok := ParseCertificateInfo(map[string][]byte{"tls.crt": cert, "tls.key": key})
	if !ok {
		t.Fatal("expected a valid certificate")
	}
	want := []string{"*.a.s24.dev", "*.b.s24.dev", "*.s24.dev"}
	if len(info.WildcardSANs) != len(want) {
		t.Fatalf("WildcardSANs = %#v, want %#v", info.WildcardSANs, want)
	}
	for i, san := range want {
		if info.WildcardSANs[i] != san {
			t.Fatalf("WildcardSANs = %#v, want %#v", info.WildcardSANs, want)
		}
	}
	if info.Fingerprint == "" {
		t.Fatal("expected a non-empty fingerprint")
	}
}

func TestParseCertificateInfoMismatchedKeyFails(t *testing.T) {
	cert, _ := generateTestCertificate(t, "a.example.com")
	_, otherKey := generateTestCertificate(t, "a.example.com")
	if _, ok := ParseCertificateInfo(map[string][]byte{"tls.crt": cert, "tls.key": otherKey}); ok {
		t.Fatal("mismatched key/cert pair must be rejected")
	}
}

func TestParseCertificateInfoValidatesCABundle(t *testing.T) {
	cert, key := generateTestCertificate(t, "a.example.com")
	caCert, _ := generateTestCertificate(t, "ca.example.com")

	t.Run("empty ca.crt is invalid", func(t *testing.T) {
		if _, ok := ParseCertificateInfo(map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": {}}); ok {
			t.Fatal("empty ca.crt must be rejected")
		}
	})
	t.Run("garbage ca.crt is invalid", func(t *testing.T) {
		if _, ok := ParseCertificateInfo(map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": []byte("not a certificate")}); ok {
			t.Fatal("malformed ca.crt must be rejected")
		}
	})
	t.Run("valid PEM ca.crt is accepted", func(t *testing.T) {
		if _, ok := ParseCertificateInfo(map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": caCert}); !ok {
			t.Fatal("valid ca.crt must be accepted")
		}
	})
	t.Run("base64-encoded ca.crt is accepted", func(t *testing.T) {
		encoded := []byte(base64.StdEncoding.EncodeToString(caCert))
		if _, ok := ParseCertificateInfo(map[string][]byte{"tls.crt": cert, "tls.key": key, "ca.crt": encoded}); !ok {
			t.Fatal("base64-encoded ca.crt must be accepted")
		}
	})
}

func TestParseCertificateInfoFingerprintIgnoresPEMWhitespace(t *testing.T) {
	cert, key := generateTestCertificate(t, "a.example.com")
	first, ok := ParseCertificateInfo(map[string][]byte{"tls.crt": cert, "tls.key": key})
	if !ok {
		t.Fatal("expected a valid certificate")
	}

	reformatted := bytes.ReplaceAll(cert, []byte("\n"), []byte("\r\n"))
	reformatted = append(reformatted, '\n', '\n')
	second, ok := ParseCertificateInfo(map[string][]byte{"tls.crt": reformatted, "tls.key": key})
	if !ok {
		t.Fatal("expected a valid certificate after re-wrapping PEM whitespace")
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprints differ across equivalent PEM encodings: %s vs %s", first.Fingerprint, second.Fingerprint)
	}
}

func TestCoveringWildcard(t *testing.T) {
	info := certInfo("fp", "*.b.s24.dev", "*.s24.dev")
	tests := []struct {
		host string
		want string
	}{
		{"a.b.s24.dev", "*.b.s24.dev"},
		{"x.s24.dev", "*.s24.dev"},
		{"a.b.c.s24.dev", ""}, // "*.b.c.s24.dev" is not a SAN
		{"*.b.s24.dev", ""},   // wildcard hosts are never themselves "covered"
		{"s24.dev", ""},       // no parent label
	}
	for _, test := range tests {
		if got := coveringWildcard(test.host, info); got != test.want {
			t.Fatalf("coveringWildcard(%q) = %q, want %q", test.host, got, test.want)
		}
	}
}
