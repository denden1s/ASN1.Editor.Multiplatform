// Package detect classifies raw input bytes and decodes them to DER.
//
// Detection order ports the WPF heuristics (FileUtility.FileToBinary,
// BinaryConverterVM, HexUtility.AnyToBinary):
//
//  1. Strict DER: the whole input must be exactly one top-level TLV
//     (asn1.ParseDER; mirrors the TagLength == filesize check).
//  2. PEM armor with one of the known OpenSSL labels.
//  3. Hex in five layouts: plain, 0x-prefixed, colon-, space- and
//     comma-separated (separators and 0x prefixes are stripped).
//  4. Whitespace-tolerant Base64 (standard encoding, then raw
//     unpadded as a fallback).
//
// Anything else is an error from DecodeInput. HEX, Base64 and PEM
// payloads are re-validated with asn1.ParseDER, so DecodeInput only
// ever returns genuine DER.
package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"unicode"

	"asn1editor/internal/asn1"
)

// Encoding is the detected input framing.
type Encoding int

const (
	EncodingDER Encoding = iota
	EncodingPEM
	EncodingHex
	EncodingBase64
)

// String returns the display name of the encoding.
func (e Encoding) String() string {
	switch e {
	case EncodingDER:
		return "DER"
	case EncodingPEM:
		return "PEM"
	case EncodingHex:
		return "HEX"
	case EncodingBase64:
		return "Base64"
	default:
		return "Unknown"
	}
}

// pemLabels is the ported BinaryConverterVM PEM list: its 25 entries are
// Base64 plus 24 OpenSSL armor labels below (PRIVATE KEY covers both the
// EVP and PKCS#8-unencrypted entries; EVP read-any adds ANY PRIVATE KEY).
var pemLabels = []string{
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

// PEMLabels returns a copy of the known PEM armor labels.
func PEMLabels() []string {
	out := make([]string, len(pemLabels))
	copy(out, pemLabels)
	return out
}

// utf8BOM is stripped before detection (FileUtility routes BOM-marked
// files through the text decoders, never raw DER).
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func stripBOM(data []byte) []byte {
	if bytes.HasPrefix(data, utf8BOM) {
		return data[len(utf8BOM):]
	}
	return data
}

func isKnownPEMLabel(label string) bool {
	for _, known := range pemLabels {
		if label == known {
			return true
		}
	}
	return false
}

func hasPEMArmor(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN "))
}

// trimPEMFrame drops surrounding whitespace before encoding/pem runs.
// pem.Decode only recognizes a BEGIN line at a line boundary, so leading
// spaces/tabs on the armor line hide the block. Called only after
// hasPEMArmor matched, never on raw DER (whose edge bytes may legally
// look like whitespace).
func trimPEMFrame(data []byte) []byte {
	return bytes.TrimSpace(data)
}

// Detect classifies data by shape and returns the encoding plus a label:
// the root TagName for DER, the armor type for PEM, "HEX" for hex and
// "Base64" for Base64. Detect never fails; unknown framing reports
// (EncodingDER, "") meaning opaque binary. Use DecodeInput for validated
// decoding.
func Detect(data []byte) (Encoding, string) {
	data = stripBOM(data)
	if len(data) == 0 {
		return EncodingDER, ""
	}
	if node, err := asn1.ParseDER(data); err == nil {
		return EncodingDER, node.TagName
	}
	if hasPEMArmor(data) {
		if block, _ := pem.Decode(trimPEMFrame(data)); block != nil {
			return EncodingPEM, block.Type
		}
		return EncodingPEM, ""
	}
	text := string(data)
	if _, err := decodeHexText(text); err == nil {
		return EncodingHex, EncodingHex.String()
	}
	if _, err := decodeBase64Text(text); err == nil {
		return EncodingBase64, EncodingBase64.String()
	}
	return EncodingDER, ""
}

// DecodeInput decodes data to DER, returning the DER bytes, the label
// (same convention as Detect) and the encoding used. DER input passes
// through as a subslice of data; other framings return fresh slices.
// The returned Encoding is a best-effort guess when err is non-nil.
func DecodeInput(data []byte) ([]byte, string, Encoding, error) {
	data = stripBOM(data)
	if len(data) == 0 {
		return nil, "", EncodingDER, fmt.Errorf("detect: empty input")
	}
	if node, err := asn1.ParseDER(data); err == nil {
		return data, node.TagName, EncodingDER, nil
	}
	if hasPEMArmor(data) {
		return decodePEMBlock(data)
	}
	text := string(data)
	if raw, err := decodeHexText(text); err == nil {
		if _, verr := asn1.ParseDER(raw); verr == nil {
			return raw, EncodingHex.String(), EncodingHex, nil
		} else {
			return nil, "", EncodingHex, fmt.Errorf("detect: HEX payload is not valid DER: %v", verr)
		}
	}
	if raw, err := decodeBase64Text(text); err == nil {
		if _, verr := asn1.ParseDER(raw); verr == nil {
			return raw, EncodingBase64.String(), EncodingBase64, nil
		} else {
			return nil, "", EncodingBase64, fmt.Errorf("detect: Base64 payload is not valid DER: %v", verr)
		}
	}
	return nil, "", EncodingDER, fmt.Errorf("detect: unrecognized input: not DER, PEM, HEX or Base64")
}

func decodePEMBlock(data []byte) ([]byte, string, Encoding, error) {
	block, _ := pem.Decode(trimPEMFrame(data))
	if block == nil {
		return nil, "", EncodingPEM, fmt.Errorf("detect: malformed PEM block")
	}
	if !isKnownPEMLabel(block.Type) {
		return nil, "", EncodingPEM, fmt.Errorf("detect: unsupported PEM label %q", block.Type)
	}
	if _, err := asn1.ParseDER(block.Bytes); err != nil {
		return nil, "", EncodingPEM, fmt.Errorf("detect: PEM %q payload is not valid DER: %v", block.Type, err)
	}
	return block.Bytes, block.Type, EncodingPEM, nil
}

// decodeHexText accepts the five WPF hex layouts: plain, 0x-prefixed and
// colon/space/comma separated. ASCII whitespace, ':' ',', and any 0x/0X
// prefix are stripped; the remaining digits must be even-count hex.
func decodeHexText(s string) ([]byte, error) {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == ':' || c == ',':
			continue
		case c == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X'):
			i++
			continue
		case c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F':
			sb.WriteByte(c)
		default:
			return nil, fmt.Errorf("detect: invalid HEX character %q", c)
		}
	}
	digits := sb.String()
	if digits == "" {
		return nil, fmt.Errorf("detect: empty HEX input")
	}
	raw, err := hex.DecodeString(digits)
	if err != nil {
		return nil, fmt.Errorf("detect: invalid HEX: %v", err)
	}
	return raw, nil
}

// decodeBase64Text accepts standard Base64 with any whitespace folded in
// (wrapped lines, spaces), falling back to raw unpadded encoding.
func decodeBase64Text(s string) ([]byte, error) {
	text := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	if text == "" {
		return nil, fmt.Errorf("detect: empty Base64 input")
	}
	if raw, err := base64.StdEncoding.DecodeString(text); err == nil {
		return raw, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("detect: invalid Base64: %v", err)
	}
	return raw, nil
}
