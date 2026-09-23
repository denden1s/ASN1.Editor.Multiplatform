// Package oid decodes ASN.1 OBJECT IDENTIFIER values and resolves them
// to friendly names through a builtin dictionary (ported from the WPF
// OID.txt) plus a user dictionary. The WinCryptoAPI fallback from
// OidResolver.cs has no Go equivalent and is intentionally omitted.
package oid

import (
	"fmt"
	"strconv"
	"strings"
)

// maxArcBytes caps the base-128 width of a single arc: 10 bytes cover
// the whole uint64 range, anything wider is an overflow.
const maxArcBytes = 10

// ParseOID decodes DER content octets of an OBJECT IDENTIFIER TLV into
// arcs and dotted form. The first subidentifier is 40*arc0+arc1, decoded
// as arc0 0/1/2 with the remainder in arc1, so arc0 can never exceed 2
// by construction (e.g. first value 180 means 2.100, not 4.20).
// Empty content, truncated base-128 and arc overflow are errors.
func ParseOID(content []byte) ([]uint64, string, error) {
	if len(content) == 0 {
		return nil, "", fmt.Errorf("oid: empty content")
	}
	subs, err := decodeSubidentifiers(content)
	if err != nil {
		return nil, "", err
	}
	first := subs[0]
	var arcs []uint64
	switch {
	case first < 40:
		arcs = append(arcs, 0, first)
	case first < 80:
		arcs = append(arcs, 1, first-40)
	default:
		arcs = append(arcs, 2, first-80)
	}
	arcs = append(arcs, subs[1:]...)
	return arcs, Dotted(arcs), nil
}

// decodeSubidentifiers splits content into base-128 big-endian values.
func decodeSubidentifiers(content []byte) ([]uint64, error) {
	var subs []uint64
	var v uint64
	width := 0
	open := false
	for _, b := range content {
		if width >= maxArcBytes {
			return nil, fmt.Errorf("oid: arc %d overflows uint64", len(subs))
		}
		if v > (^uint64(0) >> 7) {
			return nil, fmt.Errorf("oid: arc %d overflows uint64", len(subs))
		}
		v = (v << 7) | uint64(b&0x7F)
		width++
		if b&0x80 == 0 {
			subs = append(subs, v)
			v = 0
			width = 0
			open = false
		} else {
			open = true
		}
	}
	if open {
		return nil, fmt.Errorf("oid: truncated base-128 arc at end of content")
	}
	return subs, nil
}

// Dotted renders arcs in digit-dot form ("1.2.840.113549").
func Dotted(arcs []uint64) string {
	var sb strings.Builder
	for i, a := range arcs {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(strconv.FormatUint(a, 10))
	}
	return sb.String()
}

// validDotted checks digit-dot form: at least two numeric arcs, no empty
// arcs or leading zeros, first arc 0..2, second arc <= 39 when first < 2.
func validDotted(s string) error {
	if s == "" {
		return fmt.Errorf("oid: empty OID value")
	}
	arcs := strings.Split(s, ".")
	if len(arcs) < 2 {
		return fmt.Errorf("oid: %q needs at least two arcs", s)
	}
	for _, a := range arcs {
		if a == "" {
			return fmt.Errorf("oid: %q has an empty arc", s)
		}
		if len(a) > 1 && a[0] == '0' {
			return fmt.Errorf("oid: %q has a leading-zero arc", s)
		}
		for j := 0; j < len(a); j++ {
			if a[j] < '0' || a[j] > '9' {
				return fmt.Errorf("oid: %q is not digit-dot form", s)
			}
		}
	}
	first, err := strconv.ParseUint(arcs[0], 10, 64)
	if err != nil {
		return fmt.Errorf("oid: %q first arc overflows uint64", s)
	}
	if first > 2 {
		return fmt.Errorf("oid: first arc %d exceeds 2", first)
	}
	if first < 2 {
		second, err := strconv.ParseUint(arcs[1], 10, 64)
		if err != nil {
			return fmt.Errorf("oid: %q second arc overflows uint64", s)
		}
		if second > 39 {
			return fmt.Errorf("oid: second arc %d exceeds 39 for first arc %d", second, first)
		}
	}
	return nil
}
