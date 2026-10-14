package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ptr(i int) *int { return &i }

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "session.json")
	st := State{
		Version:        1,
		Tabs:           []Tab{{Path: "/tmp/a.der", View: "hex", SelectedOffset: ptr(42)}, {Path: "/tmp/b.pem", View: "cert"}},
		ActiveIndex:    1,
		SidebarVisible: true,
	}
	if err := Save(path, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != st.Version || got.ActiveIndex != st.ActiveIndex ||
		!got.SidebarVisible || len(got.Tabs) != 2 {
		t.Fatalf("got %+v want %+v", got, st)
	}
	if got.Tabs[0].Path != "/tmp/a.der" || got.Tabs[0].View != "hex" {
		t.Fatalf("tab0 %+v", got.Tabs[0])
	}
	if got.Tabs[0].SelectedOffset == nil || *got.Tabs[0].SelectedOffset != 42 {
		t.Fatalf("tab0 selectedOffset %v", got.Tabs[0].SelectedOffset)
	}
	if got.Tabs[1].SelectedOffset != nil {
		t.Fatalf("tab1 selectedOffset %v, want nil", *got.Tabs[1].SelectedOffset)
	}
	if got.Tabs[1].View != "cert" || got.Tabs[1].Path != "/tmp/b.pem" {
		t.Fatalf("tab1 %+v", got.Tabs[1])
	}
	// No temp leftovers in the directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "session.json" {
		t.Fatalf("directory holds %d entries, want only session.json", len(entries))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(raw), "\n  ") {
		t.Fatalf("JSON is not indented:\n%s", raw)
	}
}

func TestSaveEmptyTabs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	st := State{Version: 1, Tabs: nil, ActiveIndex: -1}
	if err := Save(path, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ActiveIndex != -1 || len(got.Tabs) != 0 || got.SidebarVisible {
		t.Fatalf("got %+v", got)
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	cases := map[string]State{
		"bad version": {Version: 2, Tabs: []Tab{{Path: "/a", View: "hex"}}, ActiveIndex: 0},
		"bad view":    {Version: 1, Tabs: []Tab{{Path: "/a", View: "yaml"}}, ActiveIndex: 0},
		"empty path":  {Version: 1, Tabs: []Tab{{Path: "   ", View: "hex"}}, ActiveIndex: 0},
		"dup paths": {
			Version:     1,
			Tabs:        []Tab{{Path: "/a", View: "hex"}, {Path: "/a", View: "dump"}},
			ActiveIndex: 0,
		},
		"index too big": {Version: 1, Tabs: []Tab{{Path: "/a", View: "hex"}}, ActiveIndex: 1},
		"index low":     {Version: 1, Tabs: []Tab{{Path: "/a", View: "hex"}}, ActiveIndex: -2},
		"index no tabs": {Version: 1, Tabs: nil, ActiveIndex: 0},
		"negative sel":  {Version: 1, Tabs: []Tab{{Path: "/a", View: "hex", SelectedOffset: ptr(-1)}}, ActiveIndex: 0},
	}
	for name, st := range cases {
		if err := Save(path, st); err == nil {
			t.Fatalf("%s: Save: want error", name)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected saves must not create %s (stat err %v)", path, err)
	}
}

func TestSaveOverwritesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	first := State{Version: 1, Tabs: []Tab{{Path: "/a", View: "hex"}}, ActiveIndex: 0}
	if err := Save(path, first); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	second := State{Version: 1, Tabs: []Tab{{Path: "/b", View: "convert"}}, ActiveIndex: 0, SidebarVisible: true}
	if err := Save(path, second); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Tabs) != 1 || got.Tabs[0].Path != "/b" || !got.SidebarVisible {
		t.Fatalf("got %+v, want the second state", got)
	}
}

func TestLoadMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	_, err := Load(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err %v, want os.ErrNotExist", err)
	}
}

func TestLoadInvalidContent(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"broken json":  "{not json",
		"bad version":  `{"version":9,"tabs":[],"activeIndex":-1}`,
		"bad view":     `{"version":1,"tabs":[{"path":"/a","view":"nope"}],"activeIndex":0}`,
		"index oob":    `{"version":1,"tabs":[{"path":"/a","view":"hex"}],"activeIndex":5}`,
		"empty path":   `{"version":1,"tabs":[{"path":"","view":"hex"}],"activeIndex":0}`,
		"wrong types":  `{"version":"one"}`,
		"unknown view": `{"version":1,"tabs":[{"path":"/a","view":"cert","selectedOffset":-3}],"activeIndex":0}`,
	}
	for name, body := range cases {
		path := filepath.Join(dir, "s.json")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("%s: WriteFile: %v", name, err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("%s: Load: want error", name)
		}
	}
}

func TestDefaultPath(t *testing.T) {
	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if filepath.Base(path) != "session.json" {
		t.Fatalf("base %q, want session.json", filepath.Base(path))
	}
	if filepath.Base(filepath.Dir(path)) != "ASN1Editor" {
		t.Fatalf("parent %q, want ASN1Editor", filepath.Base(filepath.Dir(path)))
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("UserConfigDir unavailable: %v", err)
	}
	if filepath.Dir(path) != filepath.Join(dir, "ASN1Editor") {
		t.Fatalf("path %q, want under %q", path, dir)
	}
}
