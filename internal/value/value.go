// Package value renders primitive TLV payloads as human-readable strings
// for the tree view. Framing stays in internal/asn1; this package only
// interprets content octets of universal primitive tags. Constructed
// nodes and non-universal classes carry no scalar value: Display returns
// "" for them (their children hold the meaning).
package value

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"asn1editor/internal/asn1"
	"asn1editor/internal/oid"
)

// Display returns the human-readable payload of n, or "" when the node
// has no scalar value (constructed or non-universal tags, unhandled
// universal tags). Malformed payloads report "<invalid>" (times report
// "<invalid time>").
func Display(n *asn1.Node) string {
	if n == nil || n.Tag.Constructed || n.Tag.Class != asn1.ClassUniversal {
		return ""
	}
	p := n.Payload()
	switch n.Tag.Number {
	case 1:
		return booleanDisplay(p)
	case 2, 10:
		return intDisplay(p)
	case 3:
		return bitStringDisplay(p)
	case 4:
		return octetStringDisplay(p)
	case 5:
		if len(p) != 0 {
			return "<invalid>"
		}
		return "NULL"
	case 6:
		if _, dotted, err := oid.ParseOID(p); err != nil {
			return "<invalid>"
		} else {
			return dotted
		}
	case 12:
		if !utf8.Valid(p) {
			return "<invalid>"
		}
		return string(p)
	case 18, 19, 20, 22, 26, 27:
		return byteStringDisplay(p)
	case 28:
		return universalStringDisplay(p)
	case 30:
		return bmpStringDisplay(p)
	case 23:
		return utcTimeDisplay(p)
	case 24:
		return generalizedTimeDisplay(p)
	default:
		return ""
	}
}

func booleanDisplay(p []byte) string {
	if len(p) != 1 {
		return "<invalid>"
	}
	if p[0] == 0x00 {
		return "FALSE"
	}
	return "TRUE"
}

// intDisplay renders two's complement as decimal plus minimal hex:
// "42 (0x2A)", "-1 (0xFF)".
func intDisplay(p []byte) string {
	if len(p) == 0 {
		return "<invalid>"
	}
	v := new(big.Int).SetBytes(p)
	if p[0]&0x80 != 0 {
		mod := new(big.Int).Lsh(big.NewInt(1), uint(8*len(p)))
		v.Sub(v, mod)
	}
	return v.String() + " (0x" + strings.ToUpper(hex.EncodeToString(minimalTwosComplement(p))) + ")"
}

// minimalTwosComplement strips redundant sign bytes: 0x00 while the next
// byte keeps its high bit clear, 0xFF while the next byte keeps it set.
func minimalTwosComplement(p []byte) []byte {
	for len(p) > 1 && p[0] == 0x00 && p[1]&0x80 == 0 {
		p = p[1:]
	}
	for len(p) > 1 && p[0] == 0xFF && p[1]&0x80 != 0 {
		p = p[1:]
	}
	return p
}

// bitStringDisplay renders "unused=N set: i,j,k (0xHEX)" or
// "unused=N (empty)". The hex suffix carries the data bytes (payload
// past the unused-count octet) and is omitted when there are none.
// The pad bits of the last content byte must be zero.
func bitStringDisplay(p []byte) string {
	if len(p) == 0 {
		return "<invalid>"
	}
	unused := int(p[0])
	if unused > 7 {
		return "<invalid>"
	}
	data := p[1:]
	total := len(data)*8 - unused
	if total < 0 {
		return "<invalid>"
	}
	if unused > 0 && total > 0 && data[len(data)-1]&byte((1<<uint(unused))-1) != 0 {
		return "<invalid>"
	}
	var set []string
	for i := 0; i < total; i++ {
		if data[i/8]&(0x80>>uint(i%8)) != 0 {
			set = append(set, strconv.Itoa(i))
		}
	}
	suffix := ""
	if len(data) > 0 {
		suffix = " (0x" + strings.ToUpper(hex.EncodeToString(data)) + ")"
	}
	if len(set) == 0 {
		return fmt.Sprintf("unused=%d (empty)%s", unused, suffix)
	}
	return fmt.Sprintf("unused=%d set: %s%s", unused, strings.Join(set, ","), suffix)
}

// octetStringDisplay quotes printable ASCII, names an embedded DER TLV
// ("contains SEQUENCE (5 bytes)") without decoding it further, and falls
// back to "<N bytes>".
func octetStringDisplay(p []byte) string {
	if isPrintableASCII(p) {
		return strconv.Quote(string(p))
	}
	if root, err := asn1.ParseDER(p); err == nil {
		return fmt.Sprintf("contains %s (%d bytes)", root.TagName, len(p))
	}
	return fmt.Sprintf("<%d bytes>", len(p))
}

func isPrintableASCII(p []byte) bool {
	for _, b := range p {
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// byteStringDisplay renders IA5/Printable/Visible/Numeric/General and
// Teletex (latin-1) strings byte-as-is.
func byteStringDisplay(p []byte) string {
	var sb strings.Builder
	for _, b := range p {
		sb.WriteRune(rune(b))
	}
	return sb.String()
}

// bmpStringDisplay decodes UTF-16BE; lone surrogates are invalid.
func bmpStringDisplay(p []byte) string {
	if len(p)%2 != 0 {
		return "<invalid>"
	}
	u16 := make([]uint16, 0, len(p)/2)
	for i := 0; i < len(p); i += 2 {
		u16 = append(u16, uint16(p[i])<<8|uint16(p[i+1]))
	}
	for i := 0; i < len(u16); i++ {
		c := u16[i]
		if c >= 0xD800 && c <= 0xDBFF {
			if i+1 >= len(u16) || u16[i+1] < 0xDC00 || u16[i+1] > 0xDFFF {
				return "<invalid>"
			}
			i++
		} else if c >= 0xDC00 && c <= 0xDFFF {
			return "<invalid>"
		}
	}
	return string(utf16.Decode(u16))
}

// universalStringDisplay decodes UTF-32BE; surrogates, out-of-range
// values and ragged tails are invalid.
func universalStringDisplay(p []byte) string {
	if len(p)%4 != 0 {
		return "<invalid>"
	}
	var sb strings.Builder
	for i := 0; i < len(p); i += 4 {
		c := uint32(p[i])<<24 | uint32(p[i+1])<<16 | uint32(p[i+2])<<8 | uint32(p[i+3])
		if c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF) {
			return "<invalid>"
		}
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// utcTimeDisplay requires YYMMDDHHMMSSZ and maps YY<50 to 20YY.
func utcTimeDisplay(p []byte) string {
	if len(p) != 13 || p[12] != 'Z' {
		return "<invalid time>"
	}
	nums, ok := digitPairs(p[:12])
	if !ok {
		return "<invalid time>"
	}
	year := nums[0]
	if year < 50 {
		year += 2000
	} else {
		year += 1900
	}
	return formatTime(year, nums[1:])
}

// generalizedTimeDisplay requires YYYYMMDDHHMMSSZ.
func generalizedTimeDisplay(p []byte) string {
	if len(p) != 15 || p[14] != 'Z' {
		return "<invalid time>"
	}
	nums, ok := digitPairs(p[:14])
	if !ok {
		return "<invalid time>"
	}
	return formatTime(nums[0]*100+nums[1], nums[2:])
}

// digitPairs parses even-count ASCII digits into two-digit numbers.
func digitPairs(p []byte) ([]int, bool) {
	if len(p)%2 != 0 {
		return nil, false
	}
	out := make([]int, 0, len(p)/2)
	for i := 0; i < len(p); i += 2 {
		a, b := p[i], p[i+1]
		if a < '0' || a > '9' || b < '0' || b > '9' {
			return nil, false
		}
		out = append(out, int(a-'0')*10+int(b-'0'))
	}
	return out, true
}

// formatTime builds a UTC time from year plus MM DD HH MM SS tail and
// rejects out-of-range components via round-trip check.
func formatTime(year int, tail []int) string {
	if len(tail) != 5 {
		return "<invalid time>"
	}
	t := time.Date(year, time.Month(tail[0]), tail[1], tail[2], tail[3], tail[4], 0, time.UTC)
	if t.Year() != year || int(t.Month()) != tail[0] || t.Day() != tail[1] ||
		t.Hour() != tail[2] || t.Minute() != tail[3] || t.Second() != tail[4] {
		return "<invalid time>"
	}
	return t.Format("2006-01-02 15:04:05 UTC")
}
