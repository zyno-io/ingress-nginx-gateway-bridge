// Copyright 2026 Zyno
// SPDX-License-Identifier: Apache-2.0

package naming

import "testing"

func TestDNSLabel(t *testing.T) {
	got := DNSLabel("My_Ingress", "*.Very.Long.Example.COM")
	if len(got) > 63 {
		t.Fatalf("label length = %d, want <= 63", len(got))
	}
	if got != DNSLabel("My_Ingress", "*.Very.Long.Example.COM") {
		t.Fatal("DNSLabel is not deterministic")
	}
	if got == DNSLabel("My_Ingress", "other.example.com") {
		t.Fatal("different inputs produced the same label")
	}
}
