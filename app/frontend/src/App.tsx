import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { OpenFile } from '../wailsjs/go/main/App';
import { OnFileDrop, OnFileDropOff } from '../wailsjs/runtime/runtime';
import { DumpPanel } from './components/DumpPanel';
import { HexView } from './components/HexView';
import { TreeView } from './components/TreeView';
import { fetchFullHex, findDeepest, flattenTree, hexToBytes, nodeTotal, nodeValue } from './asn1';
import type { AsnFile, AsnNode } from './asn1';

type View = 'hex' | 'dump';

interface DocTab {
  id: number;
  file: AsnFile;
  hex: string;
  selected: AsnNode | null;
  collapsed: Set<number>;
  view: View;
}

const SIDEBAR_KEY = 'asn1.sidebar.visible';

function messageOf(e: unknown): string {
  if (e instanceof Error) {
    return e.message;
  }
  return String(e);
}

function baseName(p: string): string {
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function App() {
  const [pathInput, setPathInput] = useState('');
  const [tabs, setTabs] = useState<DocTab[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sidebarVisible, setSidebarVisible] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(SIDEBAR_KEY) !== 'false';
    } catch {
      return true;
    }
  });

  const nextId = useRef(1);
  const tabsRef = useRef<DocTab[]>([]);
  tabsRef.current = tabs;
  const activeIdRef = useRef<number | null>(null);
  activeIdRef.current = activeId;

  const active = tabs.find((t) => t.id === activeId) ?? null;

  const toggleSidebar = useCallback(() => {
    setSidebarVisible((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem(SIDEBAR_KEY, String(next));
      } catch {
        /* storage unavailable, ignore */
      }
      return next;
    });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        toggleSidebar();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [toggleSidebar]);

  const openPaths = useCallback(async (raws: string[]) => {
    const paths = raws.map((s) => s.trim()).filter((s) => s.length > 0);
    if (paths.length === 0) {
      setError('Enter a file path first.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const known = new Map<string, number>();
      for (const t of tabsRef.current) {
        known.set(t.file.path, t.id);
      }
      for (const p of paths) {
        const hit = known.get(p);
        if (hit !== undefined) {
          setActiveId(hit);
          setPathInput(p);
          continue;
        }
        const fv = await OpenFile(p);
        const resolved = known.get(fv.path);
        if (resolved !== undefined) {
          setActiveId(resolved);
          setPathInput(fv.path);
          continue;
        }
        const total = fv.root.headerLen + fv.root.length;
        const full = await fetchFullHex(fv.path, total);
        const id = nextId.current;
        nextId.current += 1;
        known.set(fv.path, id);
        known.set(p, id);
        setTabs((prev) => [
          ...prev,
          { id, file: fv, hex: full, selected: fv.root, collapsed: new Set<number>(), view: 'hex' },
        ]);
        setActiveId(id);
        setPathInput(fv.path);
      }
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const openPath = useCallback(
    (raw: string) => {
      void openPaths([raw]);
    },
    [openPaths],
  );

  // Drag-and-drop onto the whole window (useDropTarget=false needs no
  // --wails-drop-target CSS marker). Plain browsers have no runtime —
  // the path input above stays the working fallback.
  const openRef = useRef(openPaths);
  openRef.current = openPaths;
  useEffect(() => {
    try {
      OnFileDrop((_x, _y, paths) => {
        if (paths && paths.length > 0) {
          void openRef.current(paths);
        }
      }, false);
    } catch {
      /* no Wails runtime, ignore */
    }
    return () => {
      try {
        OnFileDropOff();
      } catch {
        /* no Wails runtime, ignore */
      }
    };
  }, []);

  // Suppress the default WebView context menu (no custom menu).
  useEffect(() => {
    const onContextMenu = (e: MouseEvent) => {
      e.preventDefault();
    };
    window.addEventListener('contextmenu', onContextMenu);
    return () => window.removeEventListener('contextmenu', onContextMenu);
  }, []);

  const activateTab = useCallback((id: number) => {
    const t = tabsRef.current.find((x) => x.id === id);
    if (!t) {
      return;
    }
    setActiveId(id);
    setPathInput(t.file.path);
  }, []);

  const closeTab = useCallback((id: number) => {
    const cur = tabsRef.current;
    const idx = cur.findIndex((t) => t.id === id);
    if (idx === -1) {
      return;
    }
    const rest = cur.filter((t) => t.id !== id);
    setTabs(rest);
    if (activeIdRef.current === id) {
      if (rest.length === 0) {
        setActiveId(null);
      } else {
        const pick = rest[Math.min(idx, rest.length - 1)];
        setActiveId(pick.id);
        setPathInput(pick.file.path);
      }
    }
  }, []);

  const setActiveSelected = useCallback((n: AsnNode | null) => {
    const id = activeIdRef.current;
    if (id === null) {
      return;
    }
    setTabs((prev) => prev.map((t) => (t.id === id ? { ...t, selected: n } : t)));
  }, []);

  const setActiveView = useCallback((v: View) => {
    const id = activeIdRef.current;
    if (id === null) {
      return;
    }
    setTabs((prev) => prev.map((t) => (t.id === id ? { ...t, view: v } : t)));
  }, []);

  const toggleNode = useCallback((offset: number) => {
    const id = activeIdRef.current;
    if (id === null) {
      return;
    }
    setTabs((prev) =>
      prev.map((t) => {
        if (t.id !== id) {
          return t;
        }
        const next = new Set(t.collapsed);
        if (next.has(offset)) {
          next.delete(offset);
        } else {
          next.add(offset);
        }
        return { ...t, collapsed: next };
      }),
    );
  }, []);

  const pickOffset = useCallback(
    (off: number) => {
      if (!active) {
        return;
      }
      const n = findDeepest(active.file.root, off);
      if (n) {
        setActiveSelected(n);
      }
    },
    [active, setActiveSelected],
  );

  const bytes = useMemo(() => hexToBytes(active?.hex ?? ''), [active]);
  const nodes = useMemo(() => (active ? flattenTree(active.file.root) : []), [active]);
  const selected = active?.selected ?? null;

  return (
    <div className="app">
      <header className="topbar">
        <button
          className="sidebtn"
          onClick={toggleSidebar}
          aria-label={sidebarVisible ? 'Hide sidebar' : 'Show sidebar'}
          title="Toggle sidebar (Ctrl/Cmd+B)"
        >
          ◫
        </button>
        <div className="brand">
          <span className="brand-mark">◈</span>
          <span>ASN.1 Viewer</span>
        </div>
        <form
          className="openform"
          onSubmit={(e) => {
            e.preventDefault();
            openPath(pathInput);
          }}
        >
          <input
            className="pathinput"
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            placeholder="/path/to/cert.der — or drop a file here"
            spellCheck={false}
            aria-label="File path"
          />
          <button className="openbtn" type="submit" disabled={loading}>
            {loading ? 'Opening…' : 'Open'}
          </button>
        </form>
        {active && (
          <div className="filemeta">
            {active.file.typeHint ? (
              <span className="badge">{active.file.typeHint}</span>
            ) : (
              <span className="badge badge-dim">untyped</span>
            )}
            <span className="chip">{active.file.encoding || 'DER'}</span>
            {active.file.label && (
              <span className="chip" title={active.file.label}>
                {active.file.label}
              </span>
            )}
          </div>
        )}
      </header>

      {active && (
        <div className="filepath" title={active.file.path}>
          {active.file.path}
        </div>
      )}

      {error && (
        <div className="banner banner-error" role="alert">
          <span>{error}</span>
          <button className="banner-x" onClick={() => setError(null)} aria-label="Dismiss error">
            ✕
          </button>
        </div>
      )}

      {tabs.length > 0 && (
        <div className="filetabs" role="tablist" aria-label="Open files">
          {tabs.map((t) => (
            <div
              key={t.id}
              role="tab"
              aria-selected={t.id === active?.id}
              tabIndex={0}
              title={t.file.path}
              className={t.id === active?.id ? 'ftab ftab-active' : 'ftab'}
              onClick={() => activateTab(t.id)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  activateTab(t.id);
                }
              }}
            >
              <span className="ftab-name">{baseName(t.file.path)}</span>
              {t.file.typeHint && <span className="ftab-badge">{t.file.typeHint}</span>}
              <button
                className="ftab-x"
                aria-label={`Close ${baseName(t.file.path)}`}
                title="Close"
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(t.id);
                }}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}

      <main className={sidebarVisible ? 'workspace workspace-side' : 'workspace workspace-full'}>
        {sidebarVisible && (
          <aside className="pane tree-pane" aria-label="Structure">
            <div className="pane-head">
              <span className="pane-title">Structure</span>
              {active && <span className="pane-sub">{nodes.length} nodes</span>}
            </div>
            {active ? (
              <TreeView
                root={active.file.root}
                selectedOffset={selected?.offset ?? null}
                collapsed={active.collapsed}
                onSelect={setActiveSelected}
                onToggle={toggleNode}
              />
            ) : (
              <div className="side-empty">No file open</div>
            )}
          </aside>
        )}
        {!active ? (
          <div className="empty">
            <div className="empty-h">No file open</div>
            <p className="empty-p">
              Type a path above and press Enter, or drop a DER / PEM / HEX / Base64 file onto this
              window.
            </p>
          </div>
        ) : (
          <section className="pane detail-pane" aria-label="Details">
            <div className="pane-head">
              <div className="tabs" role="tablist">
                <button
                  role="tab"
                  aria-selected={active.view === 'hex'}
                  className={active.view === 'hex' ? 'tab tab-active' : 'tab'}
                  onClick={() => setActiveView('hex')}
                >
                  Hex · {bytes.length} B
                </button>
                <button
                  role="tab"
                  aria-selected={active.view === 'dump'}
                  className={active.view === 'dump' ? 'tab tab-active' : 'tab'}
                  onClick={() => setActiveView('dump')}
                >
                  Dump · {nodes.length}
                </button>
              </div>
            </div>
            {active.view === 'hex' ? (
              <HexView bytes={bytes} selected={selected} onPickOffset={pickOffset} />
            ) : (
              <DumpPanel
                root={active.file.root}
                selectedOffset={selected?.offset ?? null}
                onSelect={setActiveSelected}
              />
            )}
          </section>
        )}
      </main>

      <footer className="statusbar">
        {selected ? (
          <span>
            sel @{selected.offset} · hl={selected.headerLen} · l={selected.length} · total=
            {nodeTotal(selected)} · d={selected.depth} · {selected.tagName} ({selected.tag})
            {selected.oidName ? ` · ${selected.oidName}` : ''}
            {nodeValue(selected) ? ` = ${nodeValue(selected)}` : ''}
          </span>
        ) : (
          <span>—</span>
        )}
      </footer>
    </div>
  );
}

export default App;
