package asn1

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

func TestParseShortFormLeaves(t *testing.T) {
	root, err := ParseDER([]byte{0x05, 0x00}) // NULL
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	if root.Offset != 0 || root.HeaderLen != 2 || root.Length != 0 || root.Depth != 0 {
		t.Fatalf("bad framing: %+v", root)
	}
	if root.TagName != "NULL" || len(root.Children) != 0 {
		t.Fatalf("bad node: %+v", root)
	}
	if !bytes.Equal(root.Raw, []byte{0x05, 0x00}) {
		t.Fatalf("Raw not round-tripped: % X", root.Raw)
	}
}

func TestParseLongFormPrimitive(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 200)
	der := append([]byte{0x04, 0x81, 0xC8}, payload...)
	root, err := ParseDER(der)
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	if root.Length != 200 || root.HeaderLen != 3 || root.TotalLen() != 203 {
		t.Fatalf("bad framing: header %d length %d", root.HeaderLen, root.Length)
	}
	if !bytes.Equal(root.Payload(), payload) {
		t.Fatalf("payload mismatch")
	}
	if !bytes.Equal(root.Raw, der) {
		t.Fatalf("Raw not round-tripped")
	}
}

func TestParseNestedConstructed(t *testing.T) {
	// SEQUENCE { INTEGER 1, SET { BOOLEAN TRUE } }
	der := []byte{
		0x30, 0x08,
		0x02, 0x01, 0x01,
		0x31, 0x03,
		0x01, 0x01, 0xFF,
	}
	root, err := ParseDER(der)
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	if root.TagName != "SEQUENCE" || len(root.Children) != 2 {
		t.Fatalf("bad root: %+v", root)
	}
	integer := root.Children[0]
	set := root.Children[1]
	if integer.TagName != "INTEGER" || integer.Offset != 2 || integer.Depth != 1 {
		t.Fatalf("bad integer: %+v", integer)
	}
	if set.TagName != "SET" || set.Offset != 5 || len(set.Children) != 1 {
		t.Fatalf("bad set: %+v", set)
	}
	boolean := set.Children[0]
	if boolean.TagName != "BOOLEAN" || boolean.Offset != 7 || boolean.Depth != 2 {
		t.Fatalf("bad boolean: %+v", boolean)
	}
	// Children must tile the parent payload exactly.
	if got := append(append([]byte{}, integer.Raw...), set.Raw...); !bytes.Equal(got, root.Payload()) {
		t.Fatalf("children do not tile parent payload")
	}
	if !bytes.Equal(root.Raw, der) {
		t.Fatalf("root Raw not round-tripped")
	}
}

func TestParseHighTagNumberTLV(t *testing.T) {
	// CONTEXT [34] primitive, 1 content byte.
	root, err := ParseDER([]byte{0x9F, 0x22, 0x01, 0xAA})
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	if root.Tag.Class != ClassContextSpecific || root.Tag.Number != 34 {
		t.Fatalf("bad tag: %+v", root.Tag)
	}
	if root.HeaderLen != 3 || root.Length != 1 {
		t.Fatalf("bad framing: %+v", root)
	}
	if root.TagName != "CONTEXT [34]" {
		t.Fatalf("bad name %q", root.TagName)
	}
}

func TestParseTruncatedErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"tag only", []byte{0x30}},
		{"length truncated", []byte{0x30, 0x81}},
		{"content truncated", []byte{0x30, 0x03, 0x02, 0x01}},
		{"indefinite", []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}},
		{"non-minimal len", []byte{0x02, 0x81, 0x01, 0x05}},
		{"trailing data", []byte{0x05, 0x00, 0x00}},
		{"child truncated", []byte{0x30, 0x03, 0x02, 0x02, 0x01}},
	}
	for _, c := range cases {
		if _, err := ParseDER(c.raw); err == nil {
			t.Fatalf("%s: expected error", c.name)
		} else if _, ok := err.(*DecodeError); !ok {
			t.Fatalf("%s: error type %T, want *DecodeError", c.name, err)
		}
	}
}

// Round-trip fixtures: hand-built DER fragments shaped like content found
// in reference/openssl/test/certs (AlgorithmIdentifier with
// sha1WithRSAEncryption OID, Validity/Subject string payloads, and a key
// BIT STRING). Small hex constants — full certificates are not vendored.
func TestRoundTripCertLikeVectors(t *testing.T) {
	vectors := []struct{ name, hex string }{
		// SEQUENCE { INTEGER 1, NULL, OID 1.2.840.113549.1.1.5 }.
		{"algid", "3010020101050006092A864886F70D010105"},
		// SEQUENCE { UTCTime "260923000000Z", PrintableString "Test" }.
		{"validity", "3015170D3236303932333030303030305A130454657374"},
		// SEQUENCE { BIT STRING 00:DE:AD:BE, OCTET STRING CA:FE }.
		{"keybits", "300A030400DEADBE0402CAFE"},
	}
	for _, v := range vectors {
		der := mustHex(t, v.hex)
		root, err := ParseDER(der)
		if err != nil {
			t.Fatalf("%s: ParseDER: %v", v.name, err)
		}
		if !bytes.Equal(root.Raw, der) {
			t.Fatalf("%s: root Raw mismatch", v.name)
		}
		// Every constructed payload must equal the concatenation of
		// its children Raw bytes; every leaf Raw must slice the input.
		var check func(n *Node)
		check = func(n *Node) {
			if len(n.Children) == 0 {
				return
			}
			var joined []byte
			for _, c := range n.Children {
				if c.Offset < n.Offset+n.HeaderLen || c.End() > n.End() {
					t.Fatalf("%s: child out of parent bounds: %+v", v.name, c)
				}
				joined = append(joined, c.Raw...)
				check(c)
			}
			if !bytes.Equal(joined, n.Payload()) {
				t.Fatalf("%s: children do not tile %s payload", v.name, n.TagName)
			}
		}
		check(root)
	}
}

func TestDecodeErrorCarriesOffset(t *testing.T) {
	_, err := ParseDER([]byte{0x30, 0x03, 0x02, 0x02, 0x01})
	if err == nil {
		t.Fatal("expected error")
	}
	derr, ok := err.(*DecodeError)
	if !ok {
		t.Fatalf("type %T", err)
	}
	if derr.Offset != 2 {
		t.Fatalf("offset %d, want 2 (child TLV start)", derr.Offset)
	}
}
