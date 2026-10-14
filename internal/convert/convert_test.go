package convert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func makeCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Convert Test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func makeCSRDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "Convert CSR"}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

func makeSPKIDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

func makePKCS8DER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return der
}

func TestRoundTripPEM(t *testing.T) {
	der := makeCertDER(t)
	out, err := Encode(der, "CERTIFICATE", FormatPEM)
	if err != nil {
		t.Fatalf("Encode PEM: %v", err)
	}
	if !strings.HasPrefix(out, "-----BEGIN CERTIFICATE-----") || !strings.HasSuffix(out, "-----END CERTIFICATE-----\n") {
		t.Fatalf("bad PEM armor:\n%s", out)
	}
	back, label, err := Decode(out, FormatPEM)
	if err != nil {
		t.Fatalf("Decode PEM: %v", err)
	}
	if label != "CERTIFICATE" {
		t.Fatalf("label %q", label)
	}
	if hex.EncodeToString(back) != hex.EncodeToString(der) {
		t.Fatalf("PEM round-trip mismatch")
	}
}

func TestEncodePEMGuessLabel(t *testing.T) {
	out, err := Encode(makeCSRDER(t), "", FormatPEM)
	if err != nil {
		t.Fatalf("Encode PEM: %v", err)
	}
	if !strings.HasPrefix(out, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("guessed label wrong:\n%s", out)
	}
}

func TestRoundTripHex(t *testing.T) {
	der := makeCertDER(t)
	out, err := Encode(der, "", FormatHex)
	if err != nil {
		t.Fatalf("Encode HEX: %v", err)
	}
	if out != strings.ToUpper(out) {
		t.Fatalf("HEX not uppercase: %q", out[:16])
	}
	if strings.ContainsAny(out, " \n\t:") {
		t.Fatalf("HEX has separators: %q", out[:16])
	}
	back, label, err := Decode(out, FormatHex)
	if err != nil {
		t.Fatalf("Decode HEX: %v", err)
	}
	if label != "HEX" {
		t.Fatalf("label %q", label)
	}
	if hex.EncodeToString(back) != hex.EncodeToString(der) {
		t.Fatalf("HEX round-trip mismatch")
	}
}

func TestDecodeHexMessy(t *testing.T) {
	der := makeCertDER(t)
	clean := strings.ToUpper(hex.EncodeToString(der))
	// Rebuild as "0x"-prefixed, colon-separated, wrapped and lower case.
	var messy strings.Builder
	for i := 0; i < len(clean); i += 2 {
		messy.WriteString("0x")
		messy.WriteString(clean[i : i+2])
		messy.WriteString(":")
		if (i/2)%8 == 7 {
			messy.WriteString("\n  ")
		}
	}
	back, _, err := Decode(messy.String(), FormatHex)
	if err != nil {
		t.Fatalf("Decode messy HEX: %v", err)
	}
	if hex.EncodeToString(back) != hex.EncodeToString(der) {
		t.Fatalf("messy HEX round-trip mismatch")
	}
	if _, _, err := Decode("ABC", FormatHex); err == nil {
		t.Fatalf("odd HEX: want error")
	}
	if _, _, err := Decode("ZZ", FormatHex); err == nil {
		t.Fatalf("bad HEX chars: want error")
	}
}

func TestRoundTripBase64(t *testing.T) {
	der := makeCertDER(t)
	out, err := Encode(der, "", FormatBase64)
	if err != nil {
		t.Fatalf("Encode Base64: %v", err)
	}
	if strings.ContainsAny(out, " \n\t") {
		t.Fatalf("Base64 has line breaks: %q", out[:32])
	}
	back, label, err := Decode(out, FormatBase64)
	if err != nil {
		t.Fatalf("Decode Base64: %v", err)
	}
	if label != "Base64" {
		t.Fatalf("label %q", label)
	}
	if hex.EncodeToString(back) != hex.EncodeToString(der) {
		t.Fatalf("Base64 round-trip mismatch")
	}
	// Wrapped input must decode to the same bytes.
	wrapped := out[:40] + "\n" + out[40:80] + "\r\n  " + out[80:]
	back2, _, err := Decode(wrapped, FormatBase64)
	if err != nil {
		t.Fatalf("Decode wrapped Base64: %v", err)
	}
	if hex.EncodeToString(back2) != hex.EncodeToString(der) {
		t.Fatalf("wrapped Base64 round-trip mismatch")
	}
	if _, _, err := Decode("not base64!!", FormatBase64); err == nil {
		t.Fatalf("bad Base64: want error")
	}
}

func TestEncodeDERFormatRejected(t *testing.T) {
	der := makeCertDER(t)
	if _, err := Encode(der, "", FormatDER); err == nil {
		t.Fatalf("FormatDER via Encode: want error")
	}
	if got := EncodeDER(der); hex.EncodeToString(got) != hex.EncodeToString(der) {
		t.Fatalf("EncodeDER mismatch")
	}
	got := EncodeDER(der)
	got[0] ^= 0xFF
	if der[0] == got[0] {
		t.Fatalf("EncodeDER is not a copy")
	}
	if _, err := Encode(nil, "", FormatHex); err == nil {
		t.Fatalf("empty DER: want error")
	}
}

func TestLabelFor(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	smime, err := x509.CreateCertificate(rand.Reader,
		smimeTemplate(t), smimeTemplate(t), &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate(SMIME): %v", err)
	}
	cases := map[string][]byte{
		"cert":      makeCertDER(t),
		"csr":       makeCSRDER(t),
		"spki":      makeSPKIDER(t),
		"pkcs8":     makePKCS8DER(t),
		"sec1":      sec1,
		"smimeCert": smime,
	}
	want := map[string]string{
		"cert":      "CERTIFICATE",
		"csr":       "CERTIFICATE REQUEST",
		"spki":      "PUBLIC KEY",
		"pkcs8":     "PRIVATE KEY",
		"sec1":      "PRIVATE KEY",
		"smimeCert": "CERTIFICATE",
	}
	for name, der := range cases {
		if got := LabelFor(der); got != want[name] {
			t.Fatalf("%s: got %q want %q", name, got, want[name])
		}
	}
	if got := LabelFor([]byte{0x01, 0x02, 0x03, 0x04}); got != "ASN1" {
		t.Fatalf("garbage: got %q want ASN1", got)
	}
	if got := LabelFor(nil); got != "ASN1" {
		t.Fatalf("nil: got %q want ASN1", got)
	}
}

func smimeTemplate(t *testing.T) *x509.Certificate {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	return &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "smime.example.com"},
		EmailAddresses:        []string{"a@example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}
}

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"der":        FormatDER,
		"PEM":        FormatPEM,
		" hex ":      FormatHex,
		"base64":     FormatBase64,
		"der-base64": FormatBase64,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Fatalf("ParseFormat(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseFormat(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Fatalf("bad format: want error")
	}
}

func TestDecodeDERFormat(t *testing.T) {
	der := makeCertDER(t)
	back, label, err := Decode(string(der), FormatDER)
	if err != nil {
		t.Fatalf("Decode DER: %v", err)
	}
	if label != "SEQUENCE" {
		t.Fatalf("label %q want SEQUENCE", label)
	}
	if hex.EncodeToString(back) != hex.EncodeToString(der) {
		t.Fatalf("DER round-trip mismatch")
	}
	if _, _, err := Decode("", FormatDER); err == nil {
		t.Fatalf("empty DER: want error")
	}
	if _, _, err := Decode("no armor here", FormatPEM); err == nil {
		t.Fatalf("missing PEM armor: want error")
	}
}
