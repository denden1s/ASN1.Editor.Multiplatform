package oid

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Resolver maps dotted OIDs to friendly names. The builtin dictionary is
// a read-only copy of the ported data; user entries shadow builtin ones
// on Resolve and are the only ones Save/Load/Add/Remove touch.
type Resolver struct {
	builtin map[string]string
	user    map[string]string
}

// New returns a Resolver with the builtin dictionary and an empty user
// dictionary.
func New() Resolver {
	b := make(map[string]string, len(builtinOIDs))
	for k, v := range builtinOIDs {
		b[k] = v
	}
	return Resolver{builtin: b, user: map[string]string{}}
}

// Resolve returns the friendly name for a dotted OID, preferring the
// user dictionary over the builtin one.
func (r *Resolver) Resolve(dotted string) (string, bool) {
	if name, ok := r.user[dotted]; ok {
		return name, true
	}
	name, ok := r.builtin[dotted]
	return name, ok
}

// Add inserts or overwrites a user entry. The OID must be valid
// digit-dot form and the name non-blank.
func (r *Resolver) Add(dotted, name string) error {
	if err := validDotted(dotted); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("oid: empty friendly name")
	}
	r.user[dotted] = name
	return nil
}

// Remove drops a user entry, revealing the builtin one underneath.
// Removing a builtin-only or unknown OID is an error.
func (r *Resolver) Remove(dotted string) error {
	if err := validDotted(dotted); err != nil {
		return err
	}
	if _, ok := r.user[dotted]; !ok {
		return fmt.Errorf("oid: %q is not in the user dictionary", dotted)
	}
	delete(r.user, dotted)
	return nil
}

// Save writes the user dictionary to path as JSON {oid: name}.
func (r *Resolver) Save(path string) error {
	raw, err := json.MarshalIndent(r.user, "", "  ")
	if err != nil {
		return fmt.Errorf("oid: save %s: %v", path, err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0644); err != nil {
		return fmt.Errorf("oid: save %s: %v", path, err)
	}
	return nil
}

// Load replaces the user dictionary from a JSON {oid: name} file,
// validating every entry before swapping.
func (r *Resolver) Load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("oid: load %s: %v", path, err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("oid: load %s: %v", path, err)
	}
	if m == nil {
		m = map[string]string{}
	}
	for k, v := range m {
		if err := validDotted(k); err != nil {
			return fmt.Errorf("oid: load %s: bad key: %v", path, err)
		}
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("oid: load %s: empty name for %q", path, k)
		}
		m[k] = strings.TrimSpace(v)
	}
	r.user = m
	return nil
}

// FriendlyOrDotted decodes OID content octets and returns the friendly
// name, the dotted form when unknown, or an invalid-OID note when the
// content does not decode.
func (r *Resolver) FriendlyOrDotted(content []byte) string {
	_, dotted, err := ParseOID(content)
	if err != nil {
		return "invalid OID: " + strings.TrimPrefix(err.Error(), "oid: ")
	}
	if name, ok := r.Resolve(dotted); ok {
		return name
	}
	return dotted
}
