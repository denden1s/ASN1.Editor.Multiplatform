package asn1

// ParseDER parses one complete DER object. The input must contain
// exactly one top-level TLV: empty input, truncated content and
// trailing bytes are all errors. The returned tree owns copies of the
// bytes, so the caller may reuse data afterwards.
func ParseDER(data []byte) (*Node, error) {
	if len(data) == 0 {
		return nil, decodeErr(0, "empty input: expected TLV")
	}
	root, err := parseNode(data, 0, 0)
	if err != nil {
		return nil, err
	}
	if root.End() != len(data) {
		return nil, decodeErr(root.End(), "trailing data: %d byte(s) after top-level TLV", len(data)-root.End())
	}
	return root, nil
}

func parseNode(data []byte, offset, depth int) (*Node, error) {
	if depth > maxDepth {
		return nil, decodeErr(offset, "nesting too deep (limit %d)", maxDepth)
	}
	if offset >= len(data) {
		return nil, decodeErr(offset, "truncated TLV: no tag at end of input")
	}
	tag, length, headerLen, err := parseHeader(data, offset)
	if err != nil {
		return nil, err
	}
	if length < 0 || offset+headerLen+length > len(data) {
		avail := 0
		if offset+headerLen < len(data) {
			avail = len(data) - (offset + headerLen)
		}
		return nil, decodeErr(offset, "truncated content: need %d byte(s), have %d", length, avail)
	}
	total := headerLen + length
	raw := make([]byte, total)
	copy(raw, data[offset:offset+total])
	node := &Node{
		Offset:    offset,
		HeaderLen: headerLen,
		Length:    length,
		Depth:     depth,
		Tag:       tag,
		TagName:   TagName(tag),
		Raw:       raw,
	}
	if !tag.Constructed {
		return node, nil
	}
	pos := offset + headerLen
	end := pos + length
	for pos < end {
		child, err := parseNode(data, pos, depth+1)
		if err != nil {
			return nil, err
		}
		node.Children = append(node.Children, child)
		pos = child.End()
	}
	if pos != end {
		return nil, decodeErr(pos, "constructed content overrun")
	}
	return node, nil
}
