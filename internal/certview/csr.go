// CSR summary (PKCS#10 CertificationRequest), mirroring Cert: positional
// parse on top of internal/asn1, RDN/SPKI/extension rendering shared with
// certview.go. Only requests are interpreted; anything else (including
// certificates) is ErrNotRequest.
package certview

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"

	"asn1editor/internal/asn1"
	"asn1editor/internal/value"
)

// ErrNotRequest reports input that is valid DER but not a PKCS#10
// certificate request (certificates included). Its text is part of the UI
// contract: app methods forward it verbatim.
var ErrNotRequest = errors.New("not a certificate request")

// extensionRequestOID carries the requested extensions of a CSR.
const extensionRequestOID = "1.2.840.113549.1.9.14"

// RequestAttribute is one PKCS#10 Attribute: Oid is dotted, Name is the
// display name ("Certificate Extensions" for extensionRequest), Values
// holds value.Display of every SET member.
type RequestAttribute struct {
	Oid    string   `json:"oid"`
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Req is the JSON-ready certificate request summary for the request view.
type Req struct {
	Version                 int                `json:"version"`
	Subject                 string             `json:"subject"`
	SubjectAttributes       []NameAttribute    `json:"subjectAttributes"`
	PublicKeyAlgorithm      string             `json:"publicKeyAlgorithm"`
	PublicKeyAlgorithmOid   string             `json:"publicKeyAlgorithmOid"`
	PublicKeyHex            string             `json:"publicKeyHex"`
	Attributes              []RequestAttribute `json:"attributes"`
	SubjectAlternativeNames []string           `json:"subjectAlternativeNames"`
	KeyUsage                []string           `json:"keyUsage"`
	ExtendedKeyUsage        []string           `json:"extendedKeyUsage"`
	Extensions              []GenericExtension `json:"extensions"`
	SignatureAlgorithm      string             `json:"signatureAlgorithm"`
	SignatureAlgorithmOid   string             `json:"signatureAlgorithmOid"`
	SignatureHex            string             `json:"signatureHex"`
	SignatureValid          bool               `json:"signatureValid"`
}

// ParseRequest summarizes DER-encoded PKCS#10 CertificationRequest bytes.
// Valid DER that is not a request yields ErrNotRequest; the gate is
// positional: root SEQUENCE of 3 (CertificationRequestInfo with INTEGER
// version first, subject Name and subjectPublicKeyInfo shapes, optional
// [0] attributes; AlgorithmIdentifier; BIT STRING signature).
func ParseRequest(der []byte) (Req, error) {
	root, err := asn1.ParseDER(der)
	if err != nil {
		return Req{}, err
	}
	info, ok := requestGate(root)
	if !ok {
		return Req{}, ErrNotRequest
	}
	var r Req
	if v := new(big.Int).SetBytes(info.Children[0].Payload()); v.IsInt64() {
		r.Version = int(v.Int64())
	}
	r.Subject, r.SubjectAttributes = parseName(info.Children[1])
	spki := info.Children[2]
	r.PublicKeyAlgorithm, r.PublicKeyAlgorithmOid, _ = parseAlgorithmID(spki.Children[0])
	r.PublicKeyHex = publicKeySummary(spki.Children[1])
	if len(info.Children) > 3 {
		parseRequestAttributes(info.Children[3], &r)
	}
	outerSig := root.Children[1]
	r.SignatureAlgorithm, r.SignatureAlgorithmOid, _ = parseAlgorithmID(outerSig)
	if p := root.Children[2].Payload(); len(p) > 0 {
		r.SignatureHex = hex.EncodeToString(p[1:])
	}
	if csr, err := x509.ParseCertificateRequest(der); err == nil {
		r.SignatureValid = csr.CheckSignature() == nil
	}
	return r, nil
}

// requestGate checks the positional CSR skeleton and returns the
// CertificationRequestInfo node.
func requestGate(root *asn1.Node) (*asn1.Node, bool) {
	if !isSeqNode(root) || len(root.Children) != 3 {
		return nil, false
	}
	info, sigAlg, sig := root.Children[0], root.Children[1], root.Children[2]
	if !isSeqNode(info) || !isAlgorithmIDShape(sigAlg) || !isBitStringNode(sig) {
		return nil, false
	}
	if len(info.Children) < 3 || len(info.Children) > 4 {
		return nil, false
	}
	if !isIntegerNode(info.Children[0]) || len(info.Children[0].Payload()) == 0 {
		return nil, false
	}
	if !isSeqNode(info.Children[1]) {
		return nil, false
	}
	spki := info.Children[2]
	if !isSeqNode(spki) || len(spki.Children) < 2 ||
		!isAlgorithmIDShape(spki.Children[0]) || !isBitStringNode(spki.Children[1]) {
		return nil, false
	}
	if len(info.Children) == 4 && !isContext(info.Children[3], 0, true) {
		return nil, false
	}
	return info, true
}

// parseRequestAttributes records every Attribute and decodes the
// extensionRequest ones (SAN/KeyUsage/EKU mirrored from Cert, the rest
// as generic extensions). Attribute values sit directly in the [0] node:
// each Attribute is SEQUENCE { OID, SET OF values }.
func parseRequestAttributes(attrs *asn1.Node, r *Req) {
	for _, a := range attrs.Children {
		if !isSeqNode(a) || len(a.Children) == 0 || !isOIDNode(a.Children[0]) {
			continue
		}
		oidNode := a.Children[0]
		dotted := dottedOf(oidNode)
		if dotted == "" {
			continue
		}
		attr := RequestAttribute{Oid: dotted, Name: attrDisplayName(oidNode)}
		var setKids []*asn1.Node
		if len(a.Children) > 1 && isSetNode(a.Children[1]) {
			setKids = a.Children[1].Children
			for _, v := range setKids {
				attr.Values = append(attr.Values, value.Display(v))
			}
		}
		r.Attributes = append(r.Attributes, attr)
		if dotted != extensionRequestOID {
			continue
		}
		for _, v := range setKids {
			if !isSeqNode(v) {
				continue
			}
			for _, e := range v.Children {
				parseRequestExtension(e, r)
			}
		}
	}
}

// parseRequestExtension decodes one requested Extension: SAN/KeyUsage/EKU
// into the mirrored Req fields, everything else into Req.Extensions.
func parseRequestExtension(e *asn1.Node, r *Req) {
	dotted, critical, payload, ok := splitExtension(e)
	if !ok {
		return
	}
	inner, err := asn1.ParseDER(payload)
	if err != nil {
		r.Extensions = append(r.Extensions, GenericExtension{
			Oid: dotted, Critical: critical, Hex: hex.EncodeToString(payload),
		})
		return
	}
	switch dotted {
	case "2.5.29.17":
		r.SubjectAlternativeNames = append(r.SubjectAlternativeNames, collectSANs(inner)...)
	case "2.5.29.15":
		r.KeyUsage = append(r.KeyUsage, collectKeyUsage(inner)...)
	case "2.5.29.37":
		r.ExtendedKeyUsage = append(r.ExtendedKeyUsage, collectEKU(inner)...)
	default:
		r.Extensions = append(r.Extensions, GenericExtension{
			Oid: dotted, Critical: critical, Hex: hex.EncodeToString(payload),
		})
	}
}
