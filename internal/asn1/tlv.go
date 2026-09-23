// Package asn1 implements a minimal strict DER TLV core.
//
// T01 scope: raw Tag-Length-Value framing only. No decoding of values
// (INTEGER, OID, time, etc.) — that is layered on top later using
// encoding/asn1 where appropriate. This package only splits bytes into
// nodes with exact offsets so viewers and dumps can round-trip them.
package asn1

import "fmt"

// Class is the ASN.1 tag class (bits 8-7 of the identifier octet).
type Class int

const (
	ClassUniversal       Class = 0
	ClassApplication     Class = 1
	ClassContextSpecific Class = 2
	ClassPrivate         Class = 3
)

// maxTagOctets bounds high-tag-number identifier octets (excluding the
// first octet). 5 octets cover tag numbers up to 2^35, far beyond any
// legitimate DER stream, and stop malicious base-128 runs.
const maxTagOctets = 5

// maxLengthOctets bounds long-form length octets. DER lengths above
// 4 octets (> 4 GiB) are rejected; the in-memory model cannot hold them
// and no test vector needs them.
const maxLengthOctets = 4

// maxDepth bounds constructed nesting to stop stack exhaustion on
// malicious input. Real certificates nest < 10 levels deep.
const maxDepth = 128

// Tag is a decoded identifier field.
type Tag struct {
	Class       Class
	Constructed bool
	Number      int
}

// DecodeError is a framing error anchored at a byte offset.
type DecodeError struct {
	Offset int
	Msg    string
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("asn1: offset %d: %s", e.Offset, e.Msg)
}

func decodeErr(offset int, format string, args ...any) *DecodeError {
	return &DecodeError{Offset: offset, Msg: fmt.Sprintf(format, args...)}
}

// parseTag decodes the identifier field at buf[offset].
// It returns the tag and the identifier length in bytes.
func parseTag(buf []byte, offset int) (Tag, int, error) {
	if offset < 0 || offset >= len(buf) {
		return Tag{}, 0, decodeErr(offset, "truncated tag: no identifier octet")
	}
	b := buf[offset]
	class := Class((b >> 6) & 0x03)
	constructed := b&0x20 != 0
	low := int(b & 0x1F)
	if low != 0x1F {
		return Tag{Class: class, Constructed: constructed, Number: low}, 1, nil
	}
	// High-tag-number form: base-128 big-endian, MSB-terminated.
	number := 0
	consumed := 0
	pos := offset + 1
	for {
		if pos >= len(buf) {
			return Tag{}, 0, decodeErr(offset, "truncated tag: unterminated high-tag-number")
		}
		if consumed >= maxTagOctets {
			return Tag{}, 0, decodeErr(offset, "tag number too large")
		}
		octet := buf[pos]
		pos++
		consumed++
		if consumed == 1 && octet&0x7F == 0 {
			return Tag{}, 0, decodeErr(offset, "non-minimal high-tag-number encoding")
		}
		// Overflow guard before shifting 7 bits.
		if number > (int(^uint(0)>>1) >> 7) {
			return Tag{}, 0, decodeErr(offset, "tag number too large")
		}
		number = (number << 7) | int(octet&0x7F)
		if octet&0x80 == 0 {
			break
		}
	}
	if number < 31 {
		return Tag{}, 0, decodeErr(offset, "non-minimal high-tag-number encoding: %d must use short form", number)
	}
	return Tag{Class: class, Constructed: constructed, Number: number}, pos - offset, nil
}

// parseLength decodes the length field at buf[offset].
// It returns the content length and the length-field size in bytes.
//
// DER notes: indefinite form (0x80) is rejected, long form must be
// minimal (no leading zero octets, no long form for values < 128),
// and 0xFF is reserved per X.690.
func parseLength(buf []byte, offset int) (int, int, error) {
	if offset < 0 || offset >= len(buf) {
		return 0, 0, decodeErr(offset, "truncated length: no length octet")
	}
	first := buf[offset]
	if first&0x80 == 0 {
		return int(first & 0x7F), 1, nil
	}
	count := int(first & 0x7F)
	if count == 0 {
		return 0, 0, decodeErr(offset, "indefinite length not allowed in DER")
	}
	if first == 0xFF {
		return 0, 0, decodeErr(offset, "reserved length octet 0xFF")
	}
	if count > maxLengthOctets {
		return 0, 0, decodeErr(offset, "length too large: %d length octets", count)
	}
	if offset+1+count > len(buf) {
		return 0, 0, decodeErr(offset, "truncated length: need %d octets", count)
	}
	if buf[offset+1] == 0x00 {
		return 0, 0, decodeErr(offset, "non-minimal long-form length")
	}
	length := 0
	for i := 0; i < count; i++ {
		length = (length << 8) | int(buf[offset+1+i])
	}
	if length < 128 {
		return 0, 0, decodeErr(offset, "non-minimal long-form length: %d must use short form", length)
	}
	return length, 1 + count, nil
}

// parseHeader decodes identifier + length at buf[offset].
// It returns the tag, the content length and the total header length
// (identifier octets + length octets). Content bounds are checked by
// the caller so headers can be inspected independently in tests.
func parseHeader(buf []byte, offset int) (Tag, int, int, error) {
	tag, tagLen, err := parseTag(buf, offset)
	if err != nil {
		return Tag{}, 0, 0, err
	}
	length, lenLen, err := parseLength(buf, offset+tagLen)
	if err != nil {
		return Tag{}, 0, 0, err
	}
	return tag, length, tagLen + lenLen, nil
}
