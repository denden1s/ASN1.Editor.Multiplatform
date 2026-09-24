package certview

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"asn1editor/internal/asn1"
)

func makeTestCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(0x010203),
		Subject:               pkix.Name{CommonName: "Test Cert", Organization: []string{"Test Org"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"example.com", "www.example.com"},
		SubjectKeyId:          []byte{0xDE, 0xAD, 0xBE, 0xEF},
		AuthorityKeyId:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func containsAll(hay []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, h := range hay {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestParseCertificateSelfSigned(t *testing.T) {
	der := makeTestCertDER(t)
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if c.Version != 3 {
		t.Fatalf("version %d, want 3", c.Version)
	}
	if c.SerialDec != "66051" {
		t.Fatalf("serialDec %q, want %q", c.SerialDec, "66051")
	}
	if c.SerialHex != "010203" {
		t.Fatalf("serialHex %q, want %q", c.SerialHex, "010203")
	}
	if !strings.Contains(c.Subject, "CN=Test Cert") {
		t.Fatalf("subject %q lacks CN", c.Subject)
	}
	if c.Issuer != c.Subject {
		t.Fatalf("self-signed issuer %q != subject %q", c.Issuer, c.Subject)
	}
	foundCN := false
	for _, a := range c.SubjectAttributes {
		if a.Oid == "2.5.4.3" && a.Name == "CN" && a.Value == "Test Cert" {
			foundCN = true
		}
	}
	if !foundCN {
		t.Fatalf("subjectAttributes %+v lacks CN=Test Cert", c.SubjectAttributes)
	}
	if c.NotBefore == "" || c.NotAfter == "" {
		t.Fatalf("empty validity %q / %q", c.NotBefore, c.NotAfter)
	}
	if !containsAll(c.SubjectAlternativeNames, "DNS:example.com", "DNS:www.example.com") {
		t.Fatalf("SAN %q", c.SubjectAlternativeNames)
	}
	if len(c.KeyUsage) != 3 || !containsAll(c.KeyUsage, "digitalSignature", "keyEncipherment", "keyCertSign") {
		t.Fatalf("keyUsage %q", c.KeyUsage)
	}
	if len(c.ExtendedKeyUsage) != 2 ||
		!containsAll(c.ExtendedKeyUsage, "Server Authentication", "Client Authentication") {
		t.Fatalf("eku %q", c.ExtendedKeyUsage)
	}
	if c.BasicConstraints == nil || !c.BasicConstraints.CA || c.BasicConstraints.PathLen != nil {
		t.Fatalf("basicConstraints %+v, want {CA:true PathLen:nil}", c.BasicConstraints)
	}
	if c.SubjectKeyId != "deadbeef" {
		t.Fatalf("skid %q", c.SubjectKeyId)
	}
	if c.AuthorityKeyId != "deadbeef" {
		t.Fatalf("akid %q", c.AuthorityKeyId)
	}
	if c.SignatureAlgorithmOid != "1.2.840.10045.4.3.2" {
		t.Fatalf("sigAlgOid %q", c.SignatureAlgorithmOid)
	}
	if c.SignatureAlgorithm == "" || c.PublicKeyAlgorithm == "" || c.PublicKeyAlgorithmOid == "" {
		t.Fatalf("empty alg fields %+v", c)
	}
	if len(c.Fingerprints.SHA1) != 40 || len(c.Fingerprints.SHA256) != 64 {
		t.Fatalf("fingerprint lengths %q / %q", c.Fingerprints.SHA1, c.Fingerprints.SHA256)
	}
	for _, h := range []string{c.Fingerprints.SHA1, c.Fingerprints.SHA256} {
		if _, err := hex.DecodeString(h); err != nil {
			t.Fatalf("fingerprint %q not hex: %v", h, err)
		}
		if strings.ToLower(h) != h {
			t.Fatalf("fingerprint %q not lowercase", h)
		}
	}
	s1 := sha1.Sum(der)
	if want := hex.EncodeToString(s1[:]); c.Fingerprints.SHA1 != want {
		t.Fatalf("sha1 %q want %q", c.Fingerprints.SHA1, want)
	}
	s256 := sha256.Sum256(der)
	if want := hex.EncodeToString(s256[:]); c.Fingerprints.SHA256 != want {
		t.Fatalf("sha256 %q want %q", c.Fingerprints.SHA256, want)
	}
}

func TestParseCertificateRejectsCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr"}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	_, err = ParseCertificate(csrDER)
	if !errors.Is(err, ErrNotCertificate) {
		t.Fatalf("err %v, want ErrNotCertificate", err)
	}
	if err.Error() != "not an X.509 certificate" {
		t.Fatalf("err text %q", err.Error())
	}
}

func TestParseCertificateRejectsArbitraryDER(t *testing.T) {
	for name, der := range map[string][]byte{
		"bare integer": {0x02, 0x01, 0x01},
		"seq integer":  {0x30, 0x03, 0x02, 0x01, 0x01},
		"empty seq":    {0x30, 0x00},
	} {
		if _, err := ParseCertificate(der); !errors.Is(err, ErrNotCertificate) {
			t.Fatalf("%s: err %v, want ErrNotCertificate", name, err)
		}
	}
}

func TestNodeHashAllAlgos(t *testing.T) {
	der := makeTestCertDER(t)
	root, err := asn1.ParseDER(der)
	if err != nil {
		t.Fatalf("ParseDER: %v", err)
	}
	serial := root.Children[0].Children[1] // TBS [version, serial, ...]
	raw := serial.Raw
	want := map[string]string{}
	m := md5.Sum(raw)
	want["md5"] = hex.EncodeToString(m[:])
	h1 := sha1.Sum(raw)
	want["sha1"] = hex.EncodeToString(h1[:])
	h256 := sha256.Sum256(raw)
	want["sha256"] = hex.EncodeToString(h256[:])
	h384 := sha512.Sum384(raw)
	want["sha384"] = hex.EncodeToString(h384[:])
	h512 := sha512.Sum512(raw)
	want["sha512"] = hex.EncodeToString(h512[:])
	for algo, w := range want {
		got, err := NodeHashTLV(der, serial.Offset, algo)
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		if got != w {
			t.Fatalf("%s: got %q want %q", algo, got, w)
		}
	}
	if got, err := NodeHashTLV(der, 0, "SHA256"); err != nil || got == "" {
		t.Fatalf("uppercase algo: got %q err %v", got, err)
	}
}

func TestNodeHashErrors(t *testing.T) {
	der := makeTestCertDER(t)
	if _, err := NodeHashTLV(der, 0, "sha9"); err == nil {
		t.Fatalf("bad algo: want error")
	}
	if _, err := NodeHashTLV(der, len(der)+100, "sha256"); err == nil {
		t.Fatalf("bad offset: want error")
	}
	if _, err := NodeHashTLV(der, 1, "sha256"); err == nil {
		t.Fatalf("mid-header offset: want error")
	}
}
