// Command asn1cli prints a one-level DER dump of a file.
//
// Usage: asn1cli <file>
package main

import (
	"fmt"
	"os"
	"strings"

	"asn1editor/internal/asn1"
	"asn1editor/internal/detect"
)

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "asn1cli:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: asn1cli <file>")
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	der, label, enc, err := detect.DecodeInput(raw)
	if err != nil {
		return err
	}
	root, err := asn1.ParseDER(der)
	if err != nil {
		return err
	}
	fmt.Printf("encoding: %s\n", enc.String())
	fmt.Printf("label: %s\n", label)
	fmt.Printf("typehint: %s\n", typeHint(label))
	fmt.Printf("root: offset=%d tag=%s length=%d\n", root.Offset, root.TagName, root.Length)
	for _, c := range root.Children {
		fmt.Printf("  child: offset=%d tag=%s length=%d\n", c.Offset, c.TagName, c.Length)
	}
	return nil
}

// typeHint mirrors the app badge heuristic: coarse file kind by label.
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
