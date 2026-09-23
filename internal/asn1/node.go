package asn1

// Node is one raw TLV in the DER stream.
//
// Offset is the absolute offset of the identifier octet in the input
// passed to ParseDER. HeaderLen covers identifier + length octets.
// Length is the content (payload) length. Depth is 0 for the root.
// Raw holds the full TLV bytes (header + payload), copied out of the
// input so nodes stay valid after the caller reuses its buffer.
type Node struct {
	Offset    int
	HeaderLen int
	Length    int
	Depth     int
	Tag       Tag
	TagName   string
	Raw       []byte
	Children  []*Node
}

// TotalLen returns the full TLV length (header + content).
func (n *Node) TotalLen() int {
	return n.HeaderLen + n.Length
}

// End returns the absolute offset one past the last TLV byte.
func (n *Node) End() int {
	return n.Offset + n.TotalLen()
}

// Payload returns the content octets (Raw without the header).
func (n *Node) Payload() []byte {
	return n.Raw[n.HeaderLen:]
}

// IsConstructed reports the constructed bit of the tag.
func (n *Node) IsConstructed() bool {
	return n.Tag.Constructed
}
