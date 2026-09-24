package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"asn1editor/internal/asn1"
	"asn1editor/internal/certview"
	"asn1editor/internal/detect"
	"asn1editor/internal/oid"
	"asn1editor/internal/value"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// oidResolver serves FriendlyOrDotted for OID nodes (builtin dictionary).
var oidResolver = oid.New()

// NodeDTO is the JSON contract for one TLV node. Children is null for
// leaf nodes (check HasChildren). OIDName carries FriendlyOrDotted for
// OBJECT IDENTIFIER nodes and is empty otherwise. Value holds the
// human-readable payload from value.Display, or "" when the node has no
// scalar value (constructed or non-universal tags).
type NodeDTO struct {
	Offset      int       `json:"offset"`
	HeaderLen   int       `json:"headerLen"`
	Length      int       `json:"length"`
	Depth       int       `json:"depth"`
	Tag         string    `json:"tag"`
	TagName     string    `json:"tagName"`
	OIDName     string    `json:"oidName"`
	Value       string    `json:"value"`
	HasChildren bool      `json:"hasChildren"`
	Children    []NodeDTO `json:"children"`
}

// FileView is the JSON contract for an opened file. Encoding is one of
// DER/PEM/HEX/Base64, Label is the PEM armor type / DER root tag name /
// framing name, TypeHint is certificate/request/crl/key or empty.
// HexPreview holds the first 256 DER bytes as lowercase hex; use GetHex
// for arbitrary ranges.
type FileView struct {
	Path       string  `json:"path"`
	Encoding   string  `json:"encoding"`
	Label      string  `json:"label"`
	TypeHint   string  `json:"typeHint"`
	Root       NodeDTO `json:"root"`
	HexPreview string  `json:"hexPreview"`
}

// OpenFile decodes path to DER and returns the file view for the UI.
// No caching: every call re-reads and re-decodes the file.
func (a *App) OpenFile(path string) (FileView, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FileView{}, err
	}
	der, label, enc, err := detect.DecodeInput(raw)
	if err != nil {
		return FileView{}, err
	}
	root, err := asn1.ParseDER(der)
	if err != nil {
		return FileView{}, err
	}
	preview := der
	if len(preview) > 256 {
		preview = preview[:256]
	}
	return FileView{
		Path:       path,
		Encoding:   enc.String(),
		Label:      label,
		TypeHint:   typeHint(label),
		Root:       toNodeDTO(root),
		HexPreview: hex.EncodeToString(preview),
	}, nil
}

// maxHexBytes caps a single GetHex slice.
const maxHexBytes = 1 << 20

// GetHex returns DER bytes [offset, offset+length) of path as lowercase
// hex. The file is re-decoded on every call; there is no cache yet.
func (a *App) GetHex(path string, offset, length int) (string, error) {
	if offset < 0 || length < 0 {
		return "", fmt.Errorf("asn1editor: negative offset/length")
	}
	if length > maxHexBytes {
		return "", fmt.Errorf("asn1editor: length %d exceeds 1MB limit", length)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	der, _, _, err := detect.DecodeInput(raw)
	if err != nil {
		return "", err
	}
	if offset > len(der) || length > len(der)-offset {
		return "", fmt.Errorf("asn1editor: range [%d, %d) out of %d DER bytes", offset, offset+length, len(der))
	}
	return hex.EncodeToString(der[offset : offset+length]), nil
}

// CertView decodes path to DER and returns the certificate summary for
// the cert view. Non-certificates yield certview.ErrNotCertificate with
// its "not an X.509 certificate" text intact.
func (a *App) CertView(path string) (certview.Cert, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return certview.Cert{}, err
	}
	der, _, _, err := detect.DecodeInput(raw)
	if err != nil {
		return certview.Cert{}, err
	}
	cert, err := certview.ParseCertificate(der)
	if err != nil {
		if errors.Is(err, certview.ErrNotCertificate) {
			return certview.Cert{}, certview.ErrNotCertificate
		}
		return certview.Cert{}, err
	}
	return cert, nil
}

// NodeHash returns the lowercase hex hash (md5/sha1/sha256/sha384/sha512)
// of the full TLV (header included) of the node starting at offset.
func (a *App) NodeHash(path string, offset int, algo string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	der, _, _, err := detect.DecodeInput(raw)
	if err != nil {
		return "", err
	}
	return certview.NodeHashTLV(der, offset, algo)
}

// typeHint maps a detect label (usually the PEM armor type) to a coarse
// file kind for the UI badge. Unknown labels yield "".
func typeHint(label string) string {
	switch label {
	case "CERTIFICATE", "TRUSTED CERTIFICATE":
		return "certificate"
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		return "request"
	case "X509 CRL":
		return "crl"
	}
	if strings.Contains(label, "PRIVATE KEY") || strings.Contains(label, "PUBLIC KEY") {
		return "key"
	}
	return ""
}

// toNodeDTO converts a parsed TLV tree to the UI contract, resolving
// OBJECT IDENTIFIER payloads to friendly names.
func toNodeDTO(n *asn1.Node) NodeDTO {
	dto := NodeDTO{
		Offset:      n.Offset,
		HeaderLen:   n.HeaderLen,
		Length:      n.Length,
		Depth:       n.Depth,
		Tag:         tagString(n.Tag),
		TagName:     n.TagName,
		Value:       value.Display(n),
		HasChildren: len(n.Children) > 0,
	}
	if n.Tag.Class == asn1.ClassUniversal && n.Tag.Number == 6 {
		dto.OIDName = oidResolver.FriendlyOrDotted(n.Payload())
	}
	for _, c := range n.Children {
		dto.Children = append(dto.Children, toNodeDTO(c))
	}
	return dto
}

// tagString renders a machine tag descriptor: "UNIVERSAL 16",
// "APPLICATION 1", "[0]" for context-specific, "PRIVATE 2".
func tagString(t asn1.Tag) string {
	switch t.Class {
	case asn1.ClassUniversal:
		return fmt.Sprintf("UNIVERSAL %d", t.Number)
	case asn1.ClassApplication:
		return fmt.Sprintf("APPLICATION %d", t.Number)
	case asn1.ClassContextSpecific:
		return fmt.Sprintf("[%d]", t.Number)
	case asn1.ClassPrivate:
		return fmt.Sprintf("PRIVATE %d", t.Number)
	default:
		return fmt.Sprintf("CLASS %d", int(t.Class))
	}
}
