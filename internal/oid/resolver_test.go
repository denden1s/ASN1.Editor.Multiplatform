package oid

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinCount(t *testing.T) {
	if len(builtinOIDs) != 847 {
		t.Fatalf("got %d builtin entries, want 847", len(builtinOIDs))
	}
}

func TestResolveBuiltin(t *testing.T) {
	r := New()
	cases := []struct {
		dotted string
		name   string
	}{
		{"2.5.4.3", "Common Name (CN)"},
		{"2.5.4.6", "Country (C)"},
		{"2.5.29.17", "Subject Alternative Name"},
		{"1.2.840.113549.1.1.5", "sha1RSA"},
		{"1.2.840.113549.1.9.1", "Email"},
		{"0.4.0.1862.1.1", "European Qualified Certificate"},
	}
	for _, c := range cases {
		name, ok := r.Resolve(c.dotted)
		if !ok || name != c.name {
			t.Fatalf("%s: got %q,%v want %q", c.dotted, name, ok, c.name)
		}
	}
	if _, ok := r.Resolve("2.999.1"); ok {
		t.Fatal("unknown OID resolved")
	}
}

func TestUserOverrideAndRemove(t *testing.T) {
	r := New()
	if err := r.Add("2.5.4.3", "My CN"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if name, _ := r.Resolve("2.5.4.3"); name != "My CN" {
		t.Fatalf("override failed: %q", name)
	}
	// Builtin copy must be untouched: a fresh resolver still sees it.
	fresh := New()
	if name, _ := fresh.Resolve("2.5.4.3"); name != "Common Name (CN)" {
		t.Fatalf("builtin mutated: %q", name)
	}
	if err := r.Remove("2.5.4.3"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if name, _ := r.Resolve("2.5.4.3"); name != "Common Name (CN)" {
		t.Fatalf("fallback failed: %q", name)
	}
	if err := r.Remove("2.5.4.3"); err == nil {
		t.Fatal("second Remove: expected error")
	}
	if err := r.Remove("1.2.3.4.5"); err == nil {
		t.Fatal("Remove unknown: expected error")
	}
}

func TestAddValidation(t *testing.T) {
	r := New()
	bad := []struct {
		oid  string
		name string
	}{
		{"", "x"},
		{"3.4.5", "arc0 too big"},
		{"1.40.1", "arc1 too big"},
		{"1", "single arc"},
		{"1..2", "empty arc"},
		{"01.2.3", "leading zero"},
		{"a.b.c", "not digits"},
		{"1.2.3", ""},
		{"1.2.3", "   "},
	}
	for _, c := range bad {
		if err := r.Add(c.oid, c.name); err == nil {
			t.Fatalf("Add(%q,%q): expected error", c.oid, c.name)
		}
	}
	if err := r.Add("1.2.3.4", "  Padded Name  "); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if name, _ := r.Resolve("1.2.3.4"); name != "Padded Name" {
		t.Fatalf("name not trimmed: %q", name)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	r := New()
	if err := r.Add("1.2.3.4", "Custom Four"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := r.Add("2.999.1", "Custom Nine"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	path := filepath.Join(t.TempDir(), "oids.json")
	if err := r.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded := New()
	if err := loaded.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	for oid, want := range map[string]string{"1.2.3.4": "Custom Four", "2.999.1": "Custom Nine"} {
		if name, ok := loaded.Resolve(oid); !ok || name != want {
			t.Fatalf("%s: got %q,%v", oid, name, ok)
		}
	}
	// Builtin entries survive a user-only file.
	if name, _ := loaded.Resolve("2.5.4.3"); name != "Common Name (CN)" {
		t.Fatalf("builtin lost after Load: %q", name)
	}
	// Load replaces, not merges.
	if err := loaded.Load(path); err != nil {
		t.Fatalf("re-Load: %v", err)
	}
	if err := loaded.Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("Load missing: expected error")
	}
	badJSON := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badJSON, []byte(`{"3.4.5": "bad"}`), 0644); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := loaded.Load(badJSON); err == nil {
		t.Fatal("Load invalid entry: expected error")
	}
}

func TestFriendlyOrDotted(t *testing.T) {
	r := New()
	if got := r.FriendlyOrDotted([]byte{0x55, 0x04, 0x03}); got != "Common Name (CN)" {
		t.Fatalf("got %q", got)
	}
	// 2.999.1 is absent from the builtin dictionary: dotted passthrough.
	if got := r.FriendlyOrDotted([]byte{0x88, 0x37, 0x01}); got != "2.999.1" {
		t.Fatalf("got %q", got)
	}
	if err := r.Add("2.999.1", "Custom Nine"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if got := r.FriendlyOrDotted([]byte{0x88, 0x37, 0x01}); got != "Custom Nine" {
		t.Fatalf("got %q", got)
	}
	if got := r.FriendlyOrDotted([]byte{}); got != "invalid OID: empty content" {
		t.Fatalf("got %q", got)
	}
}
