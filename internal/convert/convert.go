// Package convert converts DER to and from the text framings the editor
// offers (PEM, HEX, Base64) and guesses a PEM armor label from DER shape.
//
// Format detection for file input stays in internal/detect: Decode is an
// explicit-format entry point, so it decodes exactly the framing the caller
// names instead of sniffing it. Hex cleanup mirrors the five layouts
// internal/detect accepts (plain, 0x-prefixed, colon/space/comma separated)
// and is duplicated here only because that helper is unexported.
package convert

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"asn1editor/internal/asn1"
)

// Format is an output/input framing of a DER object.
type Format int

const (
	// FormatDER is binary DER; Encode rejects it (use EncodeDER).
	FormatDER Format = iota
	// FormatPEM is PEM armor with a guessed or given label.
	FormatPEM
	// FormatHex is uppercase hex without separators or line breaks.
	FormatHex
	// FormatBase64 is standard Base64 on a single unwrapped line.
	FormatBase64
)

// Base64LineWidth is the openssl line width (64 chars) kept as a constant
// for callers that wrap the output themselves. Encode does not wrap:
// it emits one single line, which survives JSON/Wails round-trips
// unchanged and is what this app's clipboard path wants.
const Base64LineWidth = 64

// String returns the lower-case enum name used by the UI.
func (f Format) String() string {
	switch f {
	case FormatDER:
		return "der"
	case FormatPEM:
		return "pem"
	case FormatHex:
		return "hex"
	case FormatBase64:
		return "base64"
	default:
		return "unknown"
	}
}

// ParseFormat maps an enum name to a Format. Accepted (case-insensitive,
// surrounding space ignored): "der", "pem", "hex", "base64", plus the
// "der-base64" alias for base64-wrapped raw DER used by App.Convert.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "der":
		return FormatDER, nil
	case "pem":
		return FormatPEM, nil
	case "hex":
		return FormatHex, nil
	case "base64", "der-base64":
		return FormatBase64, nil
	default:
		return 0, fmt.Errorf("convert: unknown format %q (want der/pem/hex/base64)", s)
	}
}

// EncodeDER returns the binary DER unchanged (a defensive copy), for
// callers that can carry bytes. Encode cannot return binary through its
// string result.
func EncodeDER(der []byte) []byte {
	out := make([]byte, len(der))
	copy(out, der)
	return out
}

// Encode renders der in enc. label is the PEM armor type; when it is
// empty or is not a plausible PEM label, LabelFor(der) guesses one.
// FormatDER is an error here: use EncodeDER for binary output.
func Encode(der []byte, label string, enc Format) (string, error) {
	if len(der) == 0 {
		return "", fmt.Errorf("convert: empty DER")
	}
	switch enc {
	case FormatDER:
		return "", fmt.Errorf("convert: FormatDER is binary, use EncodeDER")
	case FormatPEM:
		if _, err := asn1.ParseDER(der); err != nil {
			return "", fmt.Errorf("convert: input is not valid DER: %v", err)
		}
		if strings.TrimSpace(label) == "" {
			label = LabelFor(der)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})), nil
	case FormatHex:
		return strings.ToUpper(hex.EncodeToString(der)), nil
	case FormatBase64:
		return base64.StdEncoding.EncodeToString(der), nil
	default:
		return "", fmt.Errorf("convert: unknown format %d", int(enc))
	}
}

// Decode parses text in the given framing and returns DER plus a label:
// the PEM armor type for FormatPEM, "HEX"/"Base64" for those framings and
// the DER root tag name for FormatDER. Framing errors (odd hex, bad
// Base64, missing armor) are reported; the decoded bytes are not required
// to be a complete valid TLV, so callers can repair malformed input.
func Decode(text string, from Format) ([]byte, string, error) {
	switch from {
	case FormatDER:
		der := []byte(text)
		if len(der) == 0 {
			return nil, "", fmt.Errorf("convert: empty DER input")
		}
		return der, detectLabel(der), nil
	case FormatPEM:
		block, _ := pem.Decode([]byte(strings.TrimSpace(text)))
		if block == nil {
			return nil, "", fmt.Errorf("convert: malformed or missing PEM block")
		}
		label := strings.TrimSpace(block.Type)
		if label == "" {
			return nil, "", fmt.Errorf("convert: empty PEM label")
		}
		if len(block.Bytes) == 0 {
			return nil, "", fmt.Errorf("convert: PEM %q has an empty payload", label)
		}
		return block.Bytes, label, nil
	case FormatHex:
		digits, err := cleanHex(text)
		if err != nil {
			return nil, "", err
		}
		raw, err := hex.DecodeString(digits)
		if err != nil {
			return nil, "", fmt.Errorf("convert: invalid HEX: %v", err)
		}
		return raw, "HEX", nil
	case FormatBase64:
		cleaned := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' {
				return -1
			}
			return r
		}, text)
		if cleaned == "" {
			return nil, "", fmt.Errorf("convert: empty Base64 input")
		}
		raw, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(cleaned)
		}
		if err != nil {
			return nil, "", fmt.Errorf("convert: invalid Base64: %v", err)
		}
		return raw, "Base64", nil
	default:
		return nil, "", fmt.Errorf("convert: unknown format %d", int(from))
	}
}

// cleanHex strips the separators of the five accepted hex layouts
// (ASCII whitespace, ':' ',' and any 0x/0X prefix) and reports odd
// digit counts as an error.
func cleanHex(s string) (string, error) {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' ||
			c == ':' || c == ',':
			continue
		case c == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X'):
			i++
			continue
		case c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F':
			sb.WriteByte(c)
		default:
			return "", fmt.Errorf("convert: invalid HEX character %q", c)
		}
	}
	digits := sb.String()
	if digits == "" {
		return "", fmt.Errorf("convert: empty HEX input")
	}
	if len(digits)%2 != 0 {
		return "", fmt.Errorf("convert: odd HEX digit count (%d)", len(digits))
	}
	return digits, nil
}

// detectLabel names DER input by its root tag, or "" when unparsable.
func detectLabel(der []byte) string {
	if root, err := asn1.ParseDER(der); err == nil {
		return root.TagName
	}
	return ""
}

// Shape predicates over parsed TLV nodes.
func isSeq(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 16 && n.Tag.Constructed
}

func isInt(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 2 && !n.Tag.Constructed
}

func isOctetString(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 4 && !n.Tag.Constructed
}

func isBitString(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 3 && !n.Tag.Constructed
}

func isOID(n *asn1.Node) bool {
	return n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 6 && !n.Tag.Constructed
}

func isCtx(n *asn1.Node, num int) bool {
	return n.Tag.Class == asn1.ClassContextSpecific && n.Tag.Number == num
}

// algSeqShape checks AlgorithmIdentifier SEQUENCE { OID, params? }.
func algSeqShape(n *asn1.Node) bool {
	return isSeq(n) && len(n.Children) >= 1 && isOID(n.Children[0])
}

// LabelFor guesses the PEM armor label from the TLV shape of der, without
// crypto/x509. Recognized:
//
//	Certificate      SEQUENCE { SEQUENCE { [0] version, INTEGER serial, ... }, AlgId, BIT STRING }
//	Certificate Request  SEQUENCE { SEQUENCE { INTEGER version, Name, SPKI, [0] attrs }, AlgId, BIT STRING }
//	X509 CRL         SEQUENCE { SEQUENCE { ... } }
//	PUBLIC KEY       SEQUENCE { AlgId, BIT STRING }
//	PRIVATE KEY      SEQUENCE { INTEGER 0, AlgId, OCTET STRING } (PKCS#8 / RFC 8410 / legacy)
//
// Anything else, including unparsable bytes, is "ASN1".
func LabelFor(der []byte) string {
	if len(der) == 0 {
		return "ASN1"
	}
	root, err := asn1.ParseDER(der)
	if err != nil {
		return "ASN1"
	}
	switch {
	case isSeq(root) && len(root.Children) == 3:
		body, alg, sig := root.Children[0], root.Children[1], root.Children[2]
		if isSeq(body) && algSeqShape(alg) && isBitString(sig) {
			if looksLikeTBSCertificate(body) {
				return "CERTIFICATE"
			}
			if looksLikeCertificationRequestInfo(body) {
				return "CERTIFICATE REQUEST"
			}
		}
	case isSeq(root) && len(root.Children) == 1:
		// TBSCertList / CRL: one SEQUENCE body plus signature algorithm.
		if isSeq(root.Children[0]) {
			return "X509 CRL"
		}
	}
	if looksLikeSubjectPublicKeyInfo(root) {
		return "PUBLIC KEY"
	}
	if looksLikePrivateKey(root) {
		return "PRIVATE KEY"
	}
	return "ASN1"
}

// looksLikeTBSCertificate checks the positional certificate skeleton:
// optional [0] EXPLICIT version, INTEGER serial, AlgId, Name issuer,
// 2-time validity, Name subject, SPKI.
func looksLikeTBSCertificate(tbs *asn1.Node) bool {
	base := 0
	if len(tbs.Children) > 0 && isCtx(tbs.Children[0], 0) && tbs.Children[0].Tag.Constructed {
		inner := tbs.Children[0].Children
		if len(inner) != 1 || !isInt(inner[0]) {
			return false
		}
		base = 1
	}
	kids := tbs.Children
	if len(kids) < base+6 {
		return false
	}
	if !isInt(kids[base]) || !algSeqShape(kids[base+1]) {
		return false
	}
	if !isSeq(kids[base+2]) || !isSeq(kids[base+4]) {
		return false
	}
	validity := kids[base+3]
	if !isSeq(validity) || len(validity.Children) != 2 {
		return false
	}
	for _, t := range validity.Children {
		if t.Tag.Class != asn1.ClassUniversal ||
			(t.Tag.Number != 23 && t.Tag.Number != 24) || t.Tag.Constructed {
			return false
		}
	}
	return looksLikeSubjectPublicKeyInfo(kids[base+5])
}

// looksLikeCertificationRequestInfo checks the PKCS#10 skeleton:
// INTEGER version, Name subject, SPKI and an optional [0] attributes.
func looksLikeCertificationRequestInfo(info *asn1.Node) bool {
	kids := info.Children
	if len(kids) < 3 || len(kids) > 4 {
		return false
	}
	return isInt(kids[0]) && isSeq(kids[1]) && looksLikeSubjectPublicKeyInfo(kids[2])
}

// looksLikeSubjectPublicKeyInfo checks SEQUENCE { AlgId, BIT STRING }.
func looksLikeSubjectPublicKeyInfo(n *asn1.Node) bool {
	return isSeq(n) && len(n.Children) == 2 &&
		algSeqShape(n.Children[0]) && isBitString(n.Children[1])
}

// looksLikePrivateKey covers the PKCS#8 / RFC 8410 shape
// (SEQUENCE { INTEGER 0, AlgId, OCTET STRING }) and the legacy layouts:
// SEC1 EC keys (INTEGER 1, OCTET STRING, [0]/[1]) and RSA keys
// (INTEGER 0, INTEGER modulus, INTEGER exponent). All label as
// "PRIVATE KEY" per the converter contract.
func looksLikePrivateKey(n *asn1.Node) bool {
	if !isSeq(n) || len(n.Children) < 3 {
		return false
	}
	kids := n.Children
	if !isInt(kids[0]) {
		return false
	}
	if len(kids) == 3 && algSeqShape(kids[1]) && isOctetString(kids[2]) {
		return true // PKCS#8 / RFC 8410
	}
	if len(kids) >= 4 && isOctetString(kids[1]) &&
		isCtx(kids[2], 0) && kids[2].Tag.Constructed {
		return true // SEC1 EC private key
	}
	if len(kids) >= 3 && isInt(kids[1]) && isInt(kids[2]) {
		return true // legacy RSA private key
	}
	return false
}
