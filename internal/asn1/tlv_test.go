package asn1

import "testing"

func TestParseTagShortForm(t *testing.T) {
	tag, n, err := parseTag([]byte{0x30}, 0)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if n != 1 || tag.Class != ClassUniversal || !tag.Constructed || tag.Number != 16 {
		t.Fatalf("got %+v len %d, want universal constructed 16", tag, n)
	}

	tag, n, err = parseTag([]byte{0x05}, 0)
	if err != nil {
		t.Fatalf("parseTag NULL: %v", err)
	}
	if n != 1 || tag.Class != ClassUniversal || tag.Constructed || tag.Number != 5 {
		t.Fatalf("got %+v len %d, want universal primitive 5", tag, n)
	}

	tag, _, err = parseTag([]byte{0x82}, 0)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if tag.Class != ClassContextSpecific || tag.Number != 2 {
		t.Fatalf("got %+v, want context 2", tag)
	}
}

func TestParseTagHighNumber(t *testing.T) {
	// 0x9F 0x22 = CONTEXT primitive 34.
	tag, n, err := parseTag([]byte{0x9F, 0x22}, 0)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if n != 2 || tag.Class != ClassContextSpecific || tag.Constructed || tag.Number != 34 {
		t.Fatalf("got %+v len %d, want context primitive 34", tag, n)
	}

	// 0x1F 0x81 0x01 = UNIVERSAL 129 (multi-octet base-128).
	tag, n, err = parseTag([]byte{0x1F, 0x81, 0x01}, 0)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if n != 3 || tag.Class != ClassUniversal || tag.Number != 129 {
		t.Fatalf("got %+v len %d, want universal 129", tag, n)
	}
}

func TestParseTagHighNumberRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"unterminated", []byte{0x1F}},
		{"unterminated continuation", []byte{0x9F, 0x81}},
		{"leading-zero group", []byte{0x1F, 0x80, 0x01}},
		{"short-form number", []byte{0x1F, 0x05}},
	}
	for _, c := range cases {
		if _, _, err := parseTag(c.raw, 0); err == nil {
			t.Fatalf("%s (% X): expected error", c.name, c.raw)
		}
	}
}

func TestParseLengthForms(t *testing.T) {
	l, n, err := parseLength([]byte{0x05}, 0)
	if err != nil || l != 5 || n != 1 {
		t.Fatalf("short form: got %d,%d,%v", l, n, err)
	}

	l, n, err = parseLength([]byte{0x81, 0xC8}, 0)
	if err != nil || l != 200 || n != 2 {
		t.Fatalf("long form 1 octet: got %d,%d,%v", l, n, err)
	}

	l, n, err = parseLength([]byte{0x82, 0x01, 0x00}, 0)
	if err != nil || l != 256 || n != 3 {
		t.Fatalf("long form 2 octets: got %d,%d,%v", l, n, err)
	}
}

func TestParseLengthRejectsDER(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"indefinite", []byte{0x80}},
		{"reserved 0xFF", []byte{0xFF}},
		{"non-minimal lt128", []byte{0x81, 0x05}},
		{"leading zero", []byte{0x82, 0x00, 0x80}},
		{"too many octets", []byte{0x85, 0x01, 0x00, 0x00, 0x00, 0x00}},
		{"truncated", []byte{0x82, 0x01}},
		{"empty", []byte{}},
	}
	for _, c := range cases {
		if _, _, err := parseLength(c.raw, 0); err == nil {
			t.Fatalf("%s: expected error", c.name)
		}
	}
}

func TestParseHeaderLen(t *testing.T) {
	// SEQUENCE, length 16: 1 tag octet + 1 length octet.
	_, _, hdr, err := parseHeader([]byte{0x30, 0x10}, 0)
	if err != nil || hdr != 2 {
		t.Fatalf("got hdr %d err %v, want 2", hdr, err)
	}
	// Context [34] (2 tag octets) + long-form length (2 octets).
	_, _, hdr, err = parseHeader([]byte{0x9F, 0x22, 0x81, 0xC8}, 0)
	if err != nil || hdr != 4 {
		t.Fatalf("got hdr %d err %v, want 4", hdr, err)
	}
}

func TestUniversalTagNames(t *testing.T) {
	want := map[int]string{
		1:  "BOOLEAN",
		2:  "INTEGER",
		3:  "BIT STRING",
		4:  "OCTET STRING",
		5:  "NULL",
		6:  "OBJECT IDENTIFIER",
		16: "SEQUENCE",
		17: "SET",
		23: "UTCTime",
		30: "BMPString",
	}
	for num, name := range want {
		if got := TagName(Tag{Class: ClassUniversal, Number: num}); got != name {
			t.Fatalf("universal %d: got %q want %q", num, got, name)
		}
	}
	if got := TagName(Tag{Class: ClassContextSpecific, Number: 3}); got != "CONTEXT [3]" {
		t.Fatalf("context name: got %q", got)
	}
}
