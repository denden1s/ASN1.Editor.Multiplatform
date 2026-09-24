package value

import (
	"encoding/hex"
	"testing"

	"asn1editor/internal/asn1"
)

func displayHex(t *testing.T, hx string) string {
	t.Helper()
	raw, err := hex.DecodeString(hx)
	if err != nil {
		t.Fatalf("bad fixture %q: %v", hx, err)
	}
	root, err := asn1.ParseDER(raw)
	if err != nil {
		t.Fatalf("ParseDER %q: %v", hx, err)
	}
	return Display(root)
}

func TestDisplayTable(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want string
	}{
		{"bool true", "0101FF", "TRUE"},
		{"bool false", "010100", "FALSE"},
		{"int 42", "02012A", "42 (0x2A)"},
		{"int -1", "0201FF", "-1 (0xFF)"},
		{"int 0", "020100", "0 (0x00)"},
		{"enum 3", "0A0103", "3 (0x03)"},
		{"bitstring keyusage", "030201A0", "unused=1 (0xA0)"},
		{"bitstring empty set", "030100", "unused=0 (empty)"},
		{"bitstring zero byte", "03020000", "unused=0 (0x00)"},
		{"bitstring multibyte", "03030105A0", "unused=1 (0x05A0)"},
		{"octet printable", "040568656C6C6F", `"hello"`},
		{"octet binary", "0402DEAD", "<2 bytes> (0xDEAD)"},
		{"octet with newline", "0403610A62", "\"a\\nb\""},
		{"octet binary 4 bytes", "0404DEADBEEF", "<4 bytes> (0xDEADBEEF)"},
		{"octet nested seq", "04053003020101", "SEQUENCE { INTEGER 1 (0x01) }"},
		{"octet nested two levels", "040730053003020101", "SEQUENCE { SEQUENCE { INTEGER 1 (0x01) } }"},
		{"octet nested primitive", "0403020101", "INTEGER 1 (0x01)"},
		{"octet empty seq", "04023000", "SEQUENCE {}"},
		{"octet eoc fallback", "04020000", "<2 bytes> (0x0000)"},
		{"null", "0500", "NULL"},
		{"oid commonName", "0603550403", "2.5.4.3"},
		{"printable", "130454657374", "Test"},
		{"utf8", "0C06D0B6D0B9D0BB", "жйл"},
		{"bmp AB", "1E0400410042", "AB"},
		{"universal A", "1C0400000041", "A"},
		{"utctime", "170D3236303932333030303030305A", "2026-09-23 00:00:00 UTC"},
		{"generalized", "180F32303236303932333030303030305A", "2026-09-23 00:00:00 UTC"},
		{"constructed seq", "3000", ""},
		{"context tag", "800548656C6C6F", ""},
	}
	for _, c := range cases {
		if got := displayHex(t, c.hex); got != c.want {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestDisplayInvalid(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want string
	}{
		{"bool empty", "0100", "<invalid>"},
		{"bool long", "010200FF", "<invalid>"},
		{"bitstring empty", "0300", "<invalid>"},
		{"bitstring bad pad", "030207FF", "<invalid>"},
		{"utctime no seconds", "170B323630393233303030305A", "<invalid time>"},
		{"utctime no zone", "170C323630393233303030303030", "<invalid time>"},
		{"utctime bad month", "170D3236393331333030303030305A", "<invalid time>"},
		{"bmp odd", "1E03004100", "<invalid>"},
		{"bmp lone surrogate", "1E02D800", "<invalid>"},
		{"universal ragged", "1C03000000", "<invalid>"},
		{"null with payload", "050100", "<invalid>"},
	}
	for _, c := range cases {
		if got := displayHex(t, c.hex); got != c.want {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestDisplayNil(t *testing.T) {
	if got := Display(nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestOctetEmbeddedTrimsLong(t *testing.T) {
	var content []byte
	for i := 0; i < 20; i++ {
		content = append(content, 0x02, 0x01, 0x01)
	}
	seq := append([]byte{0x30, byte(len(content))}, content...)
	oct := append([]byte{0x04, byte(len(seq))}, seq...)
	root, err := asn1.ParseDER(oct)
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	got := Display(root)
	r := []rune(got)
	if len(r) != maxOctetSummaryRunes+1 {
		t.Fatalf("rune len %d, want %d; got %q", len(r), maxOctetSummaryRunes+1, got)
	}
	if r[len(r)-1] != '…' {
		t.Fatalf("missing ellipsis terminator: %q", got)
	}
}

func TestOctetEmbeddedDepthLimit(t *testing.T) {
	inner := []byte{0x02, 0x01, 0x01}
	for i := 0; i < 4; i++ {
		inner = append([]byte{0x30, byte(len(inner))}, inner...)
	}
	oct := append([]byte{0x04, byte(len(inner))}, inner...)
	root, err := asn1.ParseDER(oct)
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	want := "SEQUENCE { SEQUENCE { SEQUENCE { SEQUENCE {...} } } }"
	if got := Display(root); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
