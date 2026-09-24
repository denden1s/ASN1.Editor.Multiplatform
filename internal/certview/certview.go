// Package certview renders X.509 certificates "as in Windows": a JSON-ready
// summary built positionally on top of internal/asn1 framing, with OID
// names from internal/oid and scalar values from internal/value.
// Only certificates are interpreted; anything else is ErrNotCertificate.
package certview

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"

	"asn1editor/internal/asn1"
	"asn1editor/internal/oid"
	"asn1editor/internal/value"
)

// ErrNotCertificate reports input that is valid DER but not an X.509
// certificate (CSR, CRL, bare TLV, ...). Its text is part of the UI
// contract: app methods forward it verbatim.
var ErrNotCertificate = errors.New("not an X.509 certificate")

// resolver maps OIDs to friendly names (builtin dictionary).
var resolver = oid.New()

// NameAttribute is one AttributeTypeAndValue of a Name: Oid is dotted,
// Name is the display short code ("CN") or the friendly name, Value is
// the human-readable attribute value.
type NameAttribute struct {
	Oid   string `json:"oid"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// BasicConstraints mirrors the 2.5.29.19 extension: CA is the cA flag,
// PathLen is nil when the extension carries no pathLenConstraint.
type BasicConstraints struct {
	CA      bool `json:"ca"`
	PathLen *int `json:"pathLen"`
}

// GenericExtension carries an extension this package does not interpret:
// Oid is dotted, Critical is the critical flag, Hex is the lowercase hex
// of the OCTET STRING payload (the inner DER bytes).
type GenericExtension struct {
	Oid      string `json:"oid"`
	Critical bool   `json:"critical"`
	Hex      string `json:"hex"`
}

// Fingerprints holds the lowercase hex digests of the full certificate DER.
type Fingerprints struct {
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// Cert is the JSON-ready certificate summary for the cert view.
type Cert struct {
	Version                  int                `json:"version"`
	SerialHex                string             `json:"serialHex"`
	SerialDec                string             `json:"serialDec"`
	SignatureAlgorithm       string             `json:"signatureAlgorithm"`
	SignatureAlgorithmOid    string             `json:"signatureAlgorithmOid"`
	SignatureAlgorithmParams string             `json:"signatureAlgorithmParams"`
	Issuer                   string             `json:"issuer"`
	IssuerAttributes         []NameAttribute    `json:"issuerAttributes"`
	Subject                  string             `json:"subject"`
	SubjectAttributes        []NameAttribute    `json:"subjectAttributes"`
	NotBefore                string             `json:"notBefore"`
	NotAfter                 string             `json:"notAfter"`
	PublicKeyAlgorithm       string             `json:"publicKeyAlgorithm"`
	PublicKeyAlgorithmOid    string             `json:"publicKeyAlgorithmOid"`
	PublicKeyHex             string             `json:"publicKeyHex"`
	SubjectAlternativeNames  []string           `json:"subjectAlternativeNames"`
	KeyUsage                 []string           `json:"keyUsage"`
	ExtendedKeyUsage         []string           `json:"extendedKeyUsage"`
	BasicConstraints         *BasicConstraints  `json:"basicConstraints"`
	SubjectKeyId             string             `json:"subjectKeyId"`
	AuthorityKeyId           string             `json:"authorityKeyId"`
	Extensions               []GenericExtension `json:"extensions"`
	Fingerprints             Fingerprints       `json:"fingerprints"`
}

// shortAttrNames abbreviates common attribute OIDs for the "CN=..." RDN
// strings; anything else falls back to the oid Resolver friendly name.
var shortAttrNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "T",
	"2.5.4.42":                   "G",
	"2.5.4.43":                   "I",
	"0.9.2342.19200300.100.1.1":  "UID",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "E",
}

// keyUsageNames lists the RFC 5280 KeyUsage bits, MSB-first.
var keyUsageNames = []string{
	"digitalSignature", "nonRepudiation", "keyEncipherment",
	"dataEncipherment", "keyAgreement", "keyCertSign",
	"cRLSign", "encipherOnly", "decipherOnly",
}

// Shape predicates over raw TLV nodes.
func isSeqNode(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 16 && n.Tag.Constructed
}

func isIntegerNode(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 2 && !n.Tag.Constructed
}

func isOIDNode(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 6 && !n.Tag.Constructed
}

func isBitStringNode(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 3 && !n.Tag.Constructed
}

func isOctetStringNode(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 4 && !n.Tag.Constructed
}

func isBoolNode(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 1 && !n.Tag.Constructed
}

func isTimeNode(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal &&
		(n.Tag.Number == 23 || n.Tag.Number == 24) && !n.Tag.Constructed
}

func isContext(n *asn1.Node, num int, constructed bool) bool {
	return n.Tag.Class == asn1.ClassContextSpecific &&
		n.Tag.Number == num && n.Tag.Constructed == constructed
}

// dottedOf decodes an OID payload to dotted form, or "" when undecodable.
func dottedOf(n *asn1.Node) string {
	_, dotted, err := oid.ParseOID(n.Payload())
	if err != nil {
		return ""
	}
	return dotted
}

// attrDisplayName renders an attribute type: short code, else the oid
// Resolver friendly name (dotted fallback).
func attrDisplayName(oidNode *asn1.Node) string {
	if short, ok := shortAttrNames[dottedOf(oidNode)]; ok {
		return short
	}
	return resolver.FriendlyOrDotted(oidNode.Payload())
}

// ParseCertificate summarizes DER-encoded X.509 Certificate bytes.
// Valid DER that is not a certificate yields ErrNotCertificate; the
// gate is positional: root SEQUENCE of 3, TBSCertificate with optional
// [0] version, INTEGER serial, AlgorithmIdentifier, issuer, a 2-time
// validity SEQUENCE, subject and subjectPublicKeyInfo.
func ParseCertificate(der []byte) (Cert, error) {
	root, err := asn1.ParseDER(der)
	if err != nil {
		return Cert{}, err
	}
	tbs, version, ok := certificateGate(root)
	if !ok {
		return Cert{}, ErrNotCertificate
	}
	// Layout past the optional version: serial, signature, issuer,
	// validity, subject, subjectPublicKeyInfo, optional [1]/[2]/[3].
	base := 0
	if version != 1 {
		base = 1
	}
	serial := tbs.Children[base]
	outerSig := root.Children[1]
	issuer := tbs.Children[base+2]
	validity := tbs.Children[base+3]
	subject := tbs.Children[base+4]
	spki := tbs.Children[base+5]

	var c Cert
	c.Version = version
	c.SerialHex = strings.ToUpper(hex.EncodeToString(stripLeadingZeros(serial.Payload())))
	c.SerialDec = new(big.Int).SetBytes(serial.Payload()).String()

	c.SignatureAlgorithm, c.SignatureAlgorithmOid, c.SignatureAlgorithmParams = parseAlgorithmID(outerSig)

	c.Issuer, c.IssuerAttributes = parseName(issuer)
	c.Subject, c.SubjectAttributes = parseName(subject)
	c.NotBefore = value.Display(validity.Children[0])
	c.NotAfter = value.Display(validity.Children[1])

	c.PublicKeyAlgorithm, c.PublicKeyAlgorithmOid, _ = parseAlgorithmID(spki.Children[0])
	c.PublicKeyHex = publicKeySummary(spki.Children[1])

	for i := base + 6; i < len(tbs.Children); i++ {
		if child := tbs.Children[i]; isContext(child, 3, true) && len(child.Children) > 0 {
			parseExtensionSequence(child.Children[0], &c)
		}
	}

	sum1 := sha1.Sum(der)
	sum256 := sha256.Sum256(der)
	c.Fingerprints = Fingerprints{
		SHA1:   hex.EncodeToString(sum1[:]),
		SHA256: hex.EncodeToString(sum256[:]),
	}
	return c, nil
}

// certificateGate checks the positional certificate skeleton and returns
// the TBSCertificate node plus the version (1/2/3).
func certificateGate(root *asn1.Node) (*asn1.Node, int, bool) {
	if !isSeqNode(root) || len(root.Children) != 3 {
		return nil, 0, false
	}
	tbs, outerSig, outerSigValue := root.Children[0], root.Children[1], root.Children[2]
	if !isSeqNode(tbs) || !isAlgorithmIDShape(outerSig) || !isBitStringNode(outerSigValue) {
		return nil, 0, false
	}
	version := 1
	base := 0
	if len(tbs.Children) > 0 && isContext(tbs.Children[0], 0, true) {
		inner := tbs.Children[0].Children
		if len(inner) != 1 || !isIntegerNode(inner[0]) {
			return nil, 0, false
		}
		v := new(big.Int).SetBytes(inner[0].Payload())
		if !v.IsInt64() || v.Int64() < 0 || v.Int64() > 2 {
			return nil, 0, false
		}
		version = int(v.Int64()) + 1
		base = 1
	}
	// serial, signature, issuer, validity, subject, subjectPublicKeyInfo.
	if len(tbs.Children) < base+6 {
		return nil, 0, false
	}
	kids := tbs.Children
	if !isIntegerNode(kids[base]) || len(kids[base].Payload()) == 0 {
		return nil, 0, false
	}
	if !isAlgorithmIDShape(kids[base+1]) {
		return nil, 0, false
	}
	if !isSeqNode(kids[base+2]) || !isSeqNode(kids[base+4]) {
		return nil, 0, false
	}
	validity := kids[base+3]
	if !isSeqNode(validity) || len(validity.Children) != 2 ||
		!isTimeNode(validity.Children[0]) || !isTimeNode(validity.Children[1]) {
		return nil, 0, false
	}
	spki := kids[base+5]
	if !isSeqNode(spki) || len(spki.Children) < 2 ||
		!isAlgorithmIDShape(spki.Children[0]) || !isBitStringNode(spki.Children[1]) {
		return nil, 0, false
	}
	return tbs, version, true
}

// isAlgorithmIDShape checks SEQUENCE with a leading OID child (params optional).
func isAlgorithmIDShape(n *asn1.Node) bool {
	return isSeqNode(n) && len(n.Children) >= 1 && isOIDNode(n.Children[0])
}

// parseAlgorithmID renders friendly name (dotted fallback), dotted OID
// and the params Display ("" when absent).
func parseAlgorithmID(n *asn1.Node) (friendly, dotted, params string) {
	oidNode := n.Children[0]
	dotted = dottedOf(oidNode)
	friendly = resolver.FriendlyOrDotted(oidNode.Payload())
	if len(n.Children) > 1 {
		params = value.Display(n.Children[1])
	}
	return friendly, dotted, params
}

// parseName renders an RDNSequence as "CN=..., OU=..." plus attributes.
// Multi-valued RDNs join with "+".
func parseName(n *asn1.Node) (string, []NameAttribute) {
	var parts []string
	var attrs []NameAttribute
	for _, set := range n.Children {
		atvs := set.Children
		if !isSetNode(set) {
			atvs = []*asn1.Node{set}
		}
		var tvs []string
		for _, atv := range atvs {
			if !isSeqNode(atv) || len(atv.Children) < 2 {
				continue
			}
			oidNode, valNode := atv.Children[0], atv.Children[1]
			if !isOIDNode(oidNode) {
				continue
			}
			name := attrDisplayName(oidNode)
			val := value.Display(valNode)
			tvs = append(tvs, name+"="+val)
			attrs = append(attrs, NameAttribute{Oid: dottedOf(oidNode), Name: name, Value: val})
		}
		if len(tvs) > 0 {
			parts = append(parts, strings.Join(tvs, "+"))
		}
	}
	return strings.Join(parts, ", "), attrs
}

func isSetNode(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 17 && n.Tag.Constructed
}

// stripLeadingZeros drops DER sign-padding zeros of a positive INTEGER.
func stripLeadingZeros(p []byte) []byte {
	for len(p) > 1 && p[0] == 0x00 {
		p = p[1:]
	}
	return p
}

// publicKeySummary hex-encodes BIT STRING key bytes (past the unused-bits
// octet), truncated to 64 hex chars with the total byte count.
func publicKeySummary(keyNode *asn1.Node) string {
	p := keyNode.Payload()
	if len(p) == 0 {
		return ""
	}
	return shortHex(p[1:])
}

// shortHex renders lowercase hex, truncated past 64 chars with the total.
func shortHex(b []byte) string {
	full := hex.EncodeToString(b)
	if len(full) <= 64 {
		return full
	}
	return fmt.Sprintf("%s…(%d bytes)", full[:64], len(b))
}

// parseExtensionSequence walks the [3] extensions SEQUENCE.
func parseExtensionSequence(seq *asn1.Node, c *Cert) {
	if !isSeqNode(seq) {
		return
	}
	for _, e := range seq.Children {
		parseExtension(e, c)
	}
}

// parseExtension decodes one Extension SEQUENCE into the Cert summary;
// unknown OIDs land in Cert.Extensions.
func parseExtension(e *asn1.Node, c *Cert) {
	if !isSeqNode(e) || len(e.Children) < 2 || len(e.Children) > 3 {
		return
	}
	oidNode := e.Children[0]
	if !isOIDNode(oidNode) {
		return
	}
	dotted := dottedOf(oidNode)
	if dotted == "" {
		return
	}
	last := e.Children[len(e.Children)-1]
	if !isOctetStringNode(last) {
		return
	}
	critical := false
	if len(e.Children) == 3 {
		flag := e.Children[1]
		if !isBoolNode(flag) || len(flag.Payload()) != 1 {
			return
		}
		critical = flag.Payload()[0] != 0x00
	}
	inner, err := asn1.ParseDER(last.Payload())
	if err != nil {
		c.Extensions = append(c.Extensions, GenericExtension{
			Oid: dotted, Critical: critical, Hex: hex.EncodeToString(last.Payload()),
		})
		return
	}
	switch dotted {
	case "2.5.29.17":
		parseSubjectAltName(inner, c)
	case "2.5.29.15":
		parseKeyUsage(inner, c)
	case "2.5.29.37":
		parseExtendedKeyUsage(inner, c)
	case "2.5.29.19":
		parseBasicConstraints(inner, c)
	case "2.5.29.14":
		if isOctetStringNode(inner) {
			c.SubjectKeyId = hex.EncodeToString(inner.Payload())
		}
	case "2.5.29.35":
		parseAuthorityKeyID(inner, c)
	default:
		c.Extensions = append(c.Extensions, GenericExtension{
			Oid: dotted, Critical: critical, Hex: hex.EncodeToString(last.Payload()),
		})
	}
}

// parseSubjectAltName renders GeneralNames: dNSName/rfc822Name/URI as
// strings, iPAddress dotted (IPv6 via net.IP), directoryName as an RDN
// summary, otherName/registeredID as OID/hex, the rest as tag/hex.
func parseSubjectAltName(inner *asn1.Node, c *Cert) {
	if !isSeqNode(inner) {
		return
	}
	for _, gn := range inner.Children {
		if gn.Tag.Class != asn1.ClassContextSpecific {
			continue
		}
		switch gn.Tag.Number {
		case 0: // otherName [0] EXPLICIT SEQUENCE { OID, [0] value }
			seqNode := gn
			if len(gn.Children) == 1 && isSeqNode(gn.Children[0]) {
				seqNode = gn.Children[0]
			}
			if isSeqNode(seqNode) && len(seqNode.Children) >= 2 && isOIDNode(seqNode.Children[0]) {
				c.SubjectAlternativeNames = append(c.SubjectAlternativeNames,
					"otherName:"+resolver.FriendlyOrDotted(seqNode.Children[0].Payload())+
						":"+hex.EncodeToString(seqNode.Children[1].Payload()))
			} else {
				c.SubjectAlternativeNames = append(c.SubjectAlternativeNames,
					"otherName:"+hex.EncodeToString(gn.Payload()))
			}
		case 1: // rfc822Name
			c.SubjectAlternativeNames = append(c.SubjectAlternativeNames, "email:"+string(gn.Payload()))
		case 2: // dNSName
			c.SubjectAlternativeNames = append(c.SubjectAlternativeNames, "DNS:"+string(gn.Payload()))
		case 4: // directoryName [4] EXPLICIT Name
			if len(gn.Children) == 1 && isSeqNode(gn.Children[0]) {
				s, _ := parseName(gn.Children[0])
				c.SubjectAlternativeNames = append(c.SubjectAlternativeNames, "DN:"+s)
			} else {
				c.SubjectAlternativeNames = append(c.SubjectAlternativeNames,
					"directoryName:"+hex.EncodeToString(gn.Payload()))
			}
		case 6: // uniformResourceIdentifier
			c.SubjectAlternativeNames = append(c.SubjectAlternativeNames, "URI:"+string(gn.Payload()))
		case 7: // iPAddress
			b := gn.Payload()
			if len(b) == 4 || len(b) == 16 {
				c.SubjectAlternativeNames = append(c.SubjectAlternativeNames, "IP:"+net.IP(b).String())
			} else {
				c.SubjectAlternativeNames = append(c.SubjectAlternativeNames, "IP:"+hex.EncodeToString(b))
			}
		case 8: // registeredID
			c.SubjectAlternativeNames = append(c.SubjectAlternativeNames,
				"RID:"+resolver.FriendlyOrDotted(gn.Payload()))
		default: // x400Address [3], ediPartyName [5], ...
			c.SubjectAlternativeNames = append(c.SubjectAlternativeNames,
				gn.TagName+":"+hex.EncodeToString(gn.Payload()))
		}
	}
}

// parseKeyUsage collects the set RFC 5280 usage bit names, MSB-first.
func parseKeyUsage(inner *asn1.Node, c *Cert) {
	if !isBitStringNode(inner) || len(inner.Payload()) == 0 {
		return
	}
	p := inner.Payload()
	data := p[1:]
	for i, b := range data {
		for bit := 0; bit < 8; bit++ {
			idx := i*8 + bit
			if idx >= len(keyUsageNames) {
				return
			}
			if b&(0x80>>uint(bit)) != 0 {
				c.KeyUsage = append(c.KeyUsage, keyUsageNames[idx])
			}
		}
	}
}

// parseExtendedKeyUsage lists EKU OIDs friendly (dotted fallback).
func parseExtendedKeyUsage(inner *asn1.Node, c *Cert) {
	if !isSeqNode(inner) {
		return
	}
	for _, o := range inner.Children {
		if !isOIDNode(o) {
			continue
		}
		c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, resolver.FriendlyOrDotted(o.Payload()))
	}
}

// parseBasicConstraints decodes cA plus optional pathLenConstraint;
// a missing pathLen stays nil (null in JSON).
func parseBasicConstraints(inner *asn1.Node, c *Cert) {
	if !isSeqNode(inner) {
		return
	}
	bc := &BasicConstraints{}
	for _, f := range inner.Children {
		switch {
		case isBoolNode(f) && len(f.Payload()) == 1:
			bc.CA = f.Payload()[0] != 0x00
		case isIntegerNode(f) && len(f.Payload()) > 0 && len(f.Payload()) <= 4:
			v := new(big.Int).SetBytes(f.Payload())
			if v.IsInt64() && v.Int64() >= 0 {
				n := int(v.Int64())
				bc.PathLen = &n
			}
		}
	}
	c.BasicConstraints = bc
}

// parseAuthorityKeyID takes the [0] keyIdentifier of the AKID SEQUENCE.
func parseAuthorityKeyID(inner *asn1.Node, c *Cert) {
	if !isSeqNode(inner) {
		return
	}
	for _, f := range inner.Children {
		if isContext(f, 0, false) {
			c.AuthorityKeyId = hex.EncodeToString(f.Payload())
			return
		}
	}
}

// NodeHashTLV hashes the full TLV (header included) of the node starting
// at offset with md5/sha1/sha256/sha384/sha512, returning lowercase hex.
// Unknown algo names and missing offsets are errors.
func NodeHashTLV(der []byte, offset int, algo string) (string, error) {
	switch strings.ToLower(algo) {
	case "md5", "sha1", "sha256", "sha384", "sha512":
	default:
		return "", fmt.Errorf("certview: unknown hash algo %q (want md5/sha1/sha256/sha384/sha512)", algo)
	}
	root, err := asn1.ParseDER(der)
	if err != nil {
		return "", err
	}
	n := findByOffset(root, offset)
	if n == nil {
		return "", fmt.Errorf("certview: no node at offset %d", offset)
	}
	var sum []byte
	switch strings.ToLower(algo) {
	case "md5":
		s := md5.Sum(n.Raw)
		sum = s[:]
	case "sha1":
		s := sha1.Sum(n.Raw)
		sum = s[:]
	case "sha256":
		s := sha256.Sum256(n.Raw)
		sum = s[:]
	case "sha384":
		s := sha512.Sum384(n.Raw)
		sum = s[:]
	case "sha512":
		s := sha512.Sum512(n.Raw)
		sum = s[:]
	}
	return hex.EncodeToString(sum), nil
}

// findByOffset returns the first node (pre-order) starting at offset.
func findByOffset(n *asn1.Node, offset int) *asn1.Node {
	if n.Offset == offset {
		return n
	}
	for _, c := range n.Children {
		if found := findByOffset(c, offset); found != nil {
			return found
		}
	}
	return nil
}
