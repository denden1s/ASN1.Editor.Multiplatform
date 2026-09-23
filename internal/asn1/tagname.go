package asn1

// TagName returns a display name for a tag: a universal type name for
// class 0, otherwise a class-qualified number such as "CONTEXT [3]".
func TagName(t Tag) string {
	if t.Class == ClassUniversal {
		if name, ok := universalNames[t.Number]; ok {
			return name
		}
		return "UNIVERSAL"
	}
	prefix := ""
	switch t.Class {
	case ClassApplication:
		prefix = "APPLICATION"
	case ClassContextSpecific:
		prefix = "CONTEXT"
	case ClassPrivate:
		prefix = "PRIVATE"
	default:
		prefix = "CLASS"
	}
	if t.Class == ClassContextSpecific {
		return itoaBracket(prefix, t.Number)
	}
	return prefix + " " + itoa(t.Number)
}

var universalNames = map[int]string{
	0:  "EOC",
	1:  "BOOLEAN",
	2:  "INTEGER",
	3:  "BIT STRING",
	4:  "OCTET STRING",
	5:  "NULL",
	6:  "OBJECT IDENTIFIER",
	7:  "ObjectDescriptor",
	8:  "EXTERNAL",
	9:  "REAL",
	10: "ENUMERATED",
	11: "EMBEDDED PDV",
	12: "UTF8String",
	13: "RELATIVE-OID",
	14: "TIME",
	15: "Reserved",
	16: "SEQUENCE",
	17: "SET",
	18: "NumericString",
	19: "PrintableString",
	20: "T61String",
	21: "VideotexString",
	22: "IA5String",
	23: "UTCTime",
	24: "GeneralizedTime",
	25: "GraphicString",
	26: "VisibleString",
	27: "GeneralString",
	28: "UniversalString",
	29: "CHARACTER STRING",
	30: "BMPString",
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var tmp [20]byte
	pos := len(tmp)
	for n > 0 {
		pos--
		tmp[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		tmp[pos] = '-'
	}
	return string(tmp[pos:])
}

func itoaBracket(prefix string, n int) string {
	return prefix + " [" + itoa(n) + "]"
}
