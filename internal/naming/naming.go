// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

// DNSLabel creates a stable DNS label no longer than 63 characters.
func DNSLabel(parts ...string) string {
	raw := strings.Join(parts, "-")
	sum := sha256.Sum256([]byte(raw))
	suffix := hex.EncodeToString(sum[:4])

	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(raw) {
		valid := unicode.IsLetter(r) || unicode.IsDigit(r)
		if valid {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	base := strings.Trim(b.String(), "-")
	if base == "" {
		base = "resource"
	}
	maxBase := 63 - len(suffix) - 1
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return base + "-" + suffix
}

// HTTPSListener returns the deterministic listener name used for a TLS hostname.
func HTTPSListener(hostname string) string {
	return DNSLabel("https", hostname)
}
