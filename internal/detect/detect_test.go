package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// Small valid DER fixtures (SEQUENCE { INTEGER 1 }, bare INTEGER 1).
var seqIntDER = []byte{0x30, 0x03, 0x02, 0x01, 0x01}

var intDER = []byte{0x02, 0x01, 0x01}

func encodePEM(t *testing.T, label string, der []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: label, Bytes: der}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeInputDERPassthrough(t *testing.T) {
	der, label, enc, err := DecodeInput(seqIntDER)
	if err != nil {
		t.Fatalf("DecodeInput: %v", err)
	}
	if enc != EncodingDER || label != "SEQUENCE" {
		t.Fatalf("got %v/%q, want DER/SEQUENCE", enc, label)
	}
	if !bytes.Equal(der, seqIntDER) {
		t.Fatalf("DER not passed through: % X", der)
	}
	if enc, label := Detect(seqIntDER); enc != EncodingDER || label != "SEQUENCE" {
		t.Fatalf("Detect: got %v/%q", enc, label)
	}
}

func TestDecodeInputPEM(t *testing.T) {
	labels := []string{"CERTIFICATE", "CERTIFICATE REQUEST", "X509 CRL", "PRIVATE KEY", "PUBLIC KEY"}
	for _, l := range labels {
		pemBytes := encodePEM(t, l, seqIntDER)
		der, label, enc, err := DecodeInput(pemBytes)
		if err != nil {
			t.Fatalf("%s: DecodeInput: %v", l, err)
		}
		if enc != EncodingPEM || label != l {
			t.Fatalf("%s: got %v/%q", l, enc, label)
		}
		if !bytes.Equal(der, seqIntDER) {
			t.Fatalf("%s: DER mismatch: % X", l, der)
		}
		if enc, label := Detect(pemBytes); enc != EncodingPEM || label != l {
			t.Fatalf("%s: Detect: got %v/%q", l, enc, label)
		}
	}
}

func TestDecodeInputPEMCRLFAndPadding(t *testing.T) {
	pemBytes := encodePEM(t, "CERTIFICATE", seqIntDER)
	crlf := []byte(strings.ReplaceAll(string(pemBytes), "\n", "\r\n"))
	if der, _, _, err := DecodeInput(crlf); err != nil || !bytes.Equal(der, seqIntDER) {
		t.Fatalf("CRLF PEM: der=% X err=%v", der, err)
	}
	padded := append([]byte("  \n\t"), append(crlf, []byte("\r\n   ")...)...)
	if der, label, enc, err := DecodeInput(padded); err != nil || !bytes.Equal(der, seqIntDER) {
		t.Fatalf("padded PEM: der=% X label=%q enc=%v err=%v", der, label, enc, err)
	} else if enc != EncodingPEM || label != "CERTIFICATE" {
		t.Fatalf("padded PEM: got %v/%q", enc, label)
	}
}

func TestDecodeInputHexVariants(t *testing.T) {
	variants := []struct {
		name string
		text string
	}{
		{"plain", "3003020101"},
		{"upper 0x", "0x30 0x03 0x02 0x01 0x01"},
		{"colon", "30:03:02:01:01"},
		{"space", "30 03 02 01 01"},
		{"comma", "30,03,02,01,01"},
		{"multiline", "30 03\n02 01\r\n01"},
		{"lower", "300a030400deadbe0402cafe"},
	}
	wantKeyBits := []byte{0x30, 0x0A, 0x03, 0x04, 0x00, 0xDE, 0xAD, 0xBE, 0x04, 0x02, 0xCA, 0xFE}
	for _, v := range variants {
		want := seqIntDER
		if v.name == "lower" {
			want = wantKeyBits
		}
		der, label, enc, err := DecodeInput([]byte(v.text))
		if err != nil {
			t.Fatalf("%s: DecodeInput: %v", v.name, err)
		}
		if enc != EncodingHex || label != "HEX" {
			t.Fatalf("%s: got %v/%q", v.name, enc, label)
		}
		if !bytes.Equal(der, want) {
			t.Fatalf("%s: DER mismatch: % X", v.name, der)
		}
		if enc, _ := Detect([]byte(v.text)); enc != EncodingHex {
			t.Fatalf("%s: Detect: got %v", v.name, enc)
		}
	}
}

func TestDecodeInputBase64(t *testing.T) {
	std := base64.StdEncoding.EncodeToString(seqIntDER)
	spaced := std[:4] + " " + std[4:8] + "\n" + std[8:] + "\r\n"
	der, label, enc, err := DecodeInput([]byte(spaced))
	if err != nil {
		t.Fatalf("spaced Base64: %v", err)
	}
	if enc != EncodingBase64 || label != "Base64" {
		t.Fatalf("got %v/%q", enc, label)
	}
	if !bytes.Equal(der, seqIntDER) {
		t.Fatalf("DER mismatch: % X", der)
	}

	raw := base64.RawStdEncoding.EncodeToString(intDER)
	if strings.Contains(raw, "=") {
		t.Fatalf("fixture has padding, pick another: %q", raw)
	}
	der, _, enc, err = DecodeInput([]byte(raw))
	if err != nil || enc != EncodingBase64 || !bytes.Equal(der, intDER) {
		t.Fatalf("raw Base64: der=% X enc=%v err=%v", der, enc, err)
	}
	if enc, label := Detect([]byte(spaced)); enc != EncodingBase64 || label != "Base64" {
		t.Fatalf("Detect: got %v/%q", enc, label)
	}
}

func TestDecodeInputErrors(t *testing.T) {
	badPEM := []byte("-----BEGIN CERTIFICATE-----\n###\n-----END CERTIFICATE-----\n")
	fooPEM := encodePEM(t, "FOO", seqIntDER)
	helloB64 := []byte(base64.StdEncoding.EncodeToString([]byte("hello")))
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"empty", []byte{}, "empty"},
		{"whitespace", []byte("  \n\t "), "unrecognized"},
		{"garbage", []byte("!!! not asn1 !!!"), "unrecognized"},
		{"truncated DER", []byte{0x30, 0x03, 0x02}, "unrecognized"},
		{"hex not DER", []byte("DEAD"), "HEX payload is not valid DER"},
		{"base64 not DER", helloB64, "Base64 payload is not valid DER"},
		{"malformed PEM", badPEM, "malformed PEM"},
		{"unsupported PEM", fooPEM, "unsupported PEM label"},
	}
	for _, c := range cases {
		if _, _, _, err := DecodeInput(c.raw); err == nil {
			t.Fatalf("%s: expected error", c.name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: error %q lacks %q", c.name, err, c.want)
		}
	}
}

func TestDetectUnknownFallsBack(t *testing.T) {
	if enc, label := Detect([]byte("!!!")); enc != EncodingDER || label != "" {
		t.Fatalf("got %v/%q, want DER/empty", enc, label)
	}
	if enc, _ := Detect([]byte{}); enc != EncodingDER {
		t.Fatalf("empty: got %v", enc)
	}
}

func TestDecodeInputBOM(t *testing.T) {
	bom := []byte{0xEF, 0xBB, 0xBF}
	inputs := [][]byte{
		append(append([]byte{}, bom...), seqIntDER...),
		append(append([]byte{}, bom...), []byte("3003020101")...),
		append(append([]byte{}, bom...), encodePEM(t, "CERTIFICATE", seqIntDER)...),
	}
	for i, in := range inputs {
		if der, _, _, err := DecodeInput(in); err != nil || !bytes.Equal(der, seqIntDER) {
			t.Fatalf("case %d: der=% X err=%v", i, der, err)
		}
	}
}

func TestPEMLabels(t *testing.T) {
	labels := PEMLabels()
	if len(labels) != 24 {
		t.Fatalf("got %d labels, want 24", len(labels))
	}
	seen := map[string]bool{}
	for _, l := range labels {
		if seen[l] {
			t.Fatalf("duplicate label %q", l)
		}
		seen[l] = true
	}
	for _, l := range labels {
		if !strings.HasPrefix(l, " ") && !strings.HasSuffix(l, " ") {
			continue
		}
		t.Fatalf("label %q has stray spaces", l)
	}
	required := []string{
		"CERTIFICATE",
		"TRUSTED CERTIFICATE",
		"NEW CERTIFICATE REQUEST",
		"CERTIFICATE REQUEST",
		"X509 CRL",
		"PRIVATE KEY",
		"PUBLIC KEY",
		"RSA PRIVATE KEY",
		"RSA PUBLIC KEY",
		"DSA PRIVATE KEY",
		"DSA PUBLIC KEY",
		"DSA PARAMETERS",
		"EC PRIVATE KEY",
		"ECDSA PUBLIC KEY",
		"EC PARAMETERS",
		"DH PARAMETERS",
		"X9.42 DH PARAMETERS",
		"PARAMETERS",
		"PKCS7",
		"PKCS #7 SIGNED DATA",
		"CMS",
		"ENCRYPTED PRIVATE KEY",
		"SSL SESSION PARAMETERS",
		"ANY PRIVATE KEY",
	}
	for _, l := range required {
		if !seen[l] {
			t.Fatalf("missing label %q", l)
		}
	}
}

func TestEncodingString(t *testing.T) {
	cases := []struct {
		enc  Encoding
		want string
	}{
		{EncodingDER, "DER"},
		{EncodingPEM, "PEM"},
		{EncodingHex, "HEX"},
		{EncodingBase64, "Base64"},
	}
	for _, c := range cases {
		if c.enc.String() != c.want {
			t.Fatalf("got %q want %q", c.enc.String(), c.want)
		}
	}
}
