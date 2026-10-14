// Package session persists the editor session: open files, the active
// detail view and the selected tree node. Storage is a small JSON file
// written atomically, so a crash mid-save can never leave a truncated
// session behind.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Version is the session file schema version this package writes and the
// only version it accepts on load.
const Version = 1

// detailViews is the whitelist of detail view kinds a Tab may name.
var detailViews = map[string]bool{
	"hex":     true,
	"dump":    true,
	"cert":    true,
	"convert": true,
}

// Tab is one open file with its detail view and selection.
// SelectedOffset is a DER byte offset into the file, or nil when nothing
// is selected. View is one of "hex", "dump", "cert", "convert".
type Tab struct {
	Path           string `json:"path"`
	View           string `json:"view"`
	SelectedOffset *int   `json:"selectedOffset"`
}

// State is the persisted session. ActiveIndex points at the active tab, or
// is -1 when no tab is active. SidebarVisible mirrors the sidebar toggle.
type State struct {
	Version        int   `json:"version"`
	Tabs           []Tab `json:"tabs"`
	ActiveIndex    int   `json:"activeIndex"`
	SidebarVisible bool  `json:"sidebarVisible"`
}

// Validate reports the first contract violation in st.
func (st *State) Validate() error {
	if st.Version != Version {
		return fmt.Errorf("session: unsupported version %d (want %d)", st.Version, Version)
	}
	if st.ActiveIndex != -1 && (st.ActiveIndex < 0 || st.ActiveIndex >= len(st.Tabs)) {
		return fmt.Errorf("session: activeIndex %d out of range for %d tab(s)", st.ActiveIndex, len(st.Tabs))
	}
	seen := make(map[string]bool, len(st.Tabs))
	for i, tab := range st.Tabs {
		path := strings.TrimSpace(tab.Path)
		if path == "" {
			return fmt.Errorf("session: tab %d has an empty path", i)
		}
		if seen[path] {
			return fmt.Errorf("session: duplicate tab path %q", path)
		}
		seen[path] = true
		if !detailViews[tab.View] {
			return fmt.Errorf("session: tab %d has unknown view %q (want hex/dump/cert/convert)", i, tab.View)
		}
		if tab.SelectedOffset != nil && *tab.SelectedOffset < 0 {
			return fmt.Errorf("session: tab %d has a negative selectedOffset %d", i, *tab.SelectedOffset)
		}
	}
	return nil
}

// Save validates st and writes it as JSON to path atomically: a temp file
// in the same directory followed by os.Rename, so readers see either the
// old or the new session, never a partial one. Missing parent directories
// are created.
func Save(path string, st State) error {
	if err := st.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("session: marshal: %v", err)
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("session: create %s: %v", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".session-*.tmp")
	if err != nil {
		return fmt.Errorf("session: temp file in %s: %v", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded

	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("session: write %s: %v", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("session: close %s: %v", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("session: rename onto %s: %v", path, err)
	}
	return nil
}

// Load reads and validates the session at path. A missing file returns
// os.ErrNotExist unchanged so callers can treat "no session yet" as a
// normal first-run state; malformed or invalid content is an error.
func Load(path string) (State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, err
		}
		return State{}, fmt.Errorf("session: read %s: %v", path, err)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, fmt.Errorf("session: parse %s: %v", path, err)
	}
	if err := st.Validate(); err != nil {
		return State{}, err
	}
	return st, nil
}

// DefaultPath returns the per-user session file location:
// <UserConfigDir>/ASN1Editor/session.json (on Windows that is %AppData%\ASN1Editor\session.json).
// The directory is created on save, not here.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("session: user config dir: %v", err)
	}
	return filepath.Join(dir, "ASN1Editor", "session.json"), nil
}
