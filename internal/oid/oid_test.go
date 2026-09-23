package oid

import (
	"bytes"
	"testing"
)

func TestParseOIDCommonName(t *testing.T) {
	arcs, dotted, err := ParseOID([]byte{0x55, 0x04, 0x03})
	if err != nil {
		t.Fatalf("ParseOID: %v", err)
	}
	wantArcs := []uint64{2, 5, 4, 3}
	if dotted != "2.5.4.3" || !equalArcs(arcs, wantArcs) {
		t.Fatalf("got %v/%q, want %v/2.5.4.3", arcs, dotted, wantArcs)
	}
}

func TestParseOIDRsaSha1(t *testing.T) {
	content := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05}
	arcs, dotted, err := ParseOID(content)
	if err != nil {
		t.Fatalf("ParseOID: %v", err)
	}
	wantArcs := []uint64{1, 2, 840, 113549, 1, 1, 5}
	if dotted != "1.2.840.113549.1.1.5" || !equalArcs(arcs, wantArcs) {
		t.Fatalf("got %v/%q", arcs, dotted)
	}
}

func TestParseOIDLongFirstArc(t *testing.T) {
	// 40*2+100 = 180 encodes as two base-128 bytes 0x81 0x34 and must
	// decode to 2.100, never to arc0 4.
	arcs, dotted, err := ParseOID([]byte{0x81, 0x34, 0x03})
	if err != nil {
		t.Fatalf("ParseOID: %v", err)
	}
	if dotted != "2.100.3" || arcs[0] != 2 {
		t.Fatalf("got %v/%q, want arc0 2", arcs, dotted)
	}
}

func TestParseOIDRejects(t *testing.T) {
	overflow := bytes.Repeat([]byte{0xFF}, 10)
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"truncated single", []byte{0x81}},
		{"truncated tail", []byte{0x2A, 0x86}},
		{"arc overflow", overflow},
	}
	for _, c := range cases {
		if _, _, err := ParseOID(c.raw); err == nil {
			t.Fatalf("%s: expected error", c.name)
		}
	}
}

func TestDotted(t *testing.T) {
	if got := Dotted([]uint64{1, 2, 840, 113549}); got != "1.2.840.113549" {
		t.Fatalf("got %q", got)
	}
	if got := Dotted(nil); got != "" {
		t.Fatalf("empty: got %q", got)
	}
}

func equalArcs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
