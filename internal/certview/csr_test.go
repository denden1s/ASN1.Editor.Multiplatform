package certview

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"asn1editor/internal/asn1"
)

func makeTestCSRDER(t *testing.T, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Test CSR"},
		DNSNames: dnsNames,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

func TestParseRequestWithSANs(t *testing.T) {
	der := makeTestCSRDER(t, []string{"example.com", "www.example.com"})
	r, err := ParseRequest(der)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if r.Version != 0 {
		t.Fatalf("version %d, want 0", r.Version)
	}
	if !strings.Contains(r.Subject, "CN=Test CSR") {
		t.Fatalf("subject %q lacks CN", r.Subject)
	}
	foundCN := false
	for _, a := range r.SubjectAttributes {
		if a.Oid == "2.5.4.3" && a.Name == "CN" && a.Value == "Test CSR" {
			foundCN = true
		}
	}
	if !foundCN {
		t.Fatalf("subjectAttributes %+v lacks CN=Test CSR", r.SubjectAttributes)
	}
	if !containsAll(r.SubjectAlternativeNames, "DNS:example.com", "DNS:www.example.com") {
		t.Fatalf("sans %q", r.SubjectAlternativeNames)
	}
	foundExtReq := false
	for _, a := range r.Attributes {
		if a.Oid == "1.2.840.113549.1.9.14" && a.Name == "Certificate Extensions" {
			foundExtReq = true
		}
	}
	if !foundExtReq {
		t.Fatalf("attributes %+v lack extensionRequest", r.Attributes)
	}
	if r.SignatureAlgorithmOid != "1.2.840.10045.4.3.2" {
		t.Fatalf("sigAlgOid %q", r.SignatureAlgorithmOid)
	}
	if r.SignatureAlgorithm != r.SignatureAlgorithmOid {
		t.Fatalf("sigAlg %q, want dotted fallback %q", r.SignatureAlgorithm, r.SignatureAlgorithmOid)
	}
	if r.SignatureHex == "" {
		t.Fatalf("empty signatureHex")
	}
	if _, err := hex.DecodeString(r.SignatureHex); err != nil {
		t.Fatalf("signatureHex not hex: %v", err)
	}
	if strings.ToLower(r.SignatureHex) != r.SignatureHex {
		t.Fatalf("signatureHex %q not lowercase", r.SignatureHex)
	}
	if !r.SignatureValid {
		t.Fatalf("signatureValid false, want true")
	}
	if r.PublicKeyAlgorithmOid == "" || r.PublicKeyAlgorithm == "" || r.PublicKeyHex == "" {
		t.Fatalf("empty public key fields %+v", r)
	}
}

func TestParseRequestBadSignature(t *testing.T) {
	der := makeTestCSRDER(t, []string{"example.com"})
	root, err := asn1.ParseDER(der)
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	sig := root.Children[2]
	bad := make([]byte, len(der))
	copy(bad, der)
	bad[sig.Offset+sig.HeaderLen+sig.Length-1] ^= 0x01
	r, err := ParseRequest(bad)
	if err != nil {
		t.Fatalf("ParseRequest of bit-flipped DER: %v (DER must stay valid)", err)
	}
	if r.SignatureValid {
		t.Fatalf("signatureValid true after bit flip, want false")
	}
}

func TestParseRequestRejectsNonCSR(t *testing.T) {
	if _, err := ParseRequest(makeTestCertDER(t)); !errors.Is(err, ErrNotRequest) {
		t.Fatalf("cert: err %v, want ErrNotRequest", err)
	}
	for name, der := range map[string][]byte{
		"bare integer": {0x02, 0x01, 0x01},
		"seq integer":  {0x30, 0x03, 0x02, 0x01, 0x01},
	} {
		_, err := ParseRequest(der)
		if !errors.Is(err, ErrNotRequest) {
			t.Fatalf("%s: err %v, want ErrNotRequest", name, err)
		}
		if err.Error() != "not a certificate request" {
			t.Fatalf("%s: err text %q", name, err.Error())
		}
	}
}

func TestParseRequestMinimal(t *testing.T) {
	der := makeTestCSRDER(t, nil)
	r, err := ParseRequest(der)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if !strings.Contains(r.Subject, "CN=Test CSR") {
		t.Fatalf("subject %q lacks CN", r.Subject)
	}
	if len(r.Attributes) != 0 {
		t.Fatalf("attributes %+v, want empty", r.Attributes)
	}
	if len(r.SubjectAlternativeNames) != 0 || len(r.KeyUsage) != 0 ||
		len(r.ExtendedKeyUsage) != 0 || len(r.Extensions) != 0 {
		t.Fatalf("want empty requested extensions, got %+v", r)
	}
	if !r.SignatureValid {
		t.Fatalf("signatureValid false, want true")
	}
}
