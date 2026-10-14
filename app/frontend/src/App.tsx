import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { CertView as fetchCertView, OpenFile, ReqView as fetchReqView } from '../wailsjs/go/main/App';
import { OnFileDrop, OnFileDropOff } from '../wailsjs/runtime/runtime';
import { CertView } from './components/CertView';
import { ConvertPanel } from './components/ConvertPanel';
import { ReqView } from './components/ReqView';
import { DumpPanel } from './components/DumpPanel';
import { HexView } from './components/HexView';
import { NodeHashBar } from './components/NodeHashBar';
import { SplitLayout } from './components/SplitLayout';
import { TreeView } from './components/TreeView';
import { fetchFullHex, findDeepest, flattenTree, hexToBytes, nodeTotal, nodeValue, VIEWS } from './asn1';
import { defaultSessionPath, loadSessionChecked, normalize, saveSession } from './session';
import type { AsnCert, AsnFile, AsnNode, AsnReq, View } from './asn1';

const SPLIT_DEFAULT_SECOND: View = 'dump';

interface DocTab {
  id: number;
  file: AsnFile;
  hex: string;
  selected: AsnNode | null;
  collapsed: Set<number>;
  view: View;
  cert: AsnCert | null;
  certError: string | null;
  req: AsnReq | null;
  reqError: string | null;
  split: boolean;
  splitView: View;
  ratio: number;
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

function certTabEmpty(t: DocTab): string {
  if (t.certError && !/not an x\.509 certificate/i.test(t.certError)) {
    return t.certError;
  }
  if (t.reqError && !/not a certificate request/i.test(t.reqError)) {
    return t.reqError;
  }
  return 'Not a certificate or request';
}

function CertTabContent({ tab }: { tab: DocTab }) {
  if (tab.cert) {
    return <CertView cert={tab.cert} certError={tab.certError} />;
  }
  if (tab.req) {
    return <ReqView req={tab.req} reqError={tab.reqError} />;
  }
  return <div className="cert-empty">{certTabEmpty(tab)}</div>;
}

function viewTitle(v: View): string {
  switch (v) {
    case 'hex':
      return 'Hex';
    case 'dump':
      return 'Dump';
    case 'cert':
      return 'Cert';
    default:
      return 'Convert';
  }
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
  const [sessionNote, setSessionNote] = useState<string | null>(null);

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

  /** Load one file into a fresh tab (throws on failure). */
  const buildTab = useCallback(async (p: string, id: number): Promise<DocTab> => {
    const fv = await OpenFile(p);
    const total = fv.root.headerLen + fv.root.length;
    const full = await fetchFullHex(fv.path, total);
    let cert: AsnCert | null = null;
    let certError: string | null = null;
    let req: AsnReq | null = null;
    let reqError: string | null = null;
    try {
      cert = await fetchCertView(fv.path);
    } catch (e) {
      certError = messageOf(e);
      if (/not an x\.509 certificate/i.test(certError)) {
        try {
          req = await fetchReqView(fv.path);
        } catch (e2) {
          reqError = messageOf(e2);
        }
      }
    }
    return {
      id,
      file: fv,
      hex: full,
      selected: fv.root,
      collapsed: new Set<number>(),
      view: fv.typeHint === 'request' ? 'cert' : 'hex',
      cert,
      certError,
      req,
      reqError,
      split: false,
      splitView: SPLIT_DEFAULT_SECOND,
      ratio: 0.5,
    };
  }, []);

  const openPaths = useCallback(
    async (raws: string[]) => {
      const paths = raws.map((s) => s.trim()).filter((s) => s.length > 0);
      if (paths.length === 0) {
        setError('Enter a file path first.');
        return;
      }
      setLoading(true);
      setError(null);
      const failures: string[] = [];
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
          const id = nextId.current;
          nextId.current += 1;
          try {
            const tab = await buildTab(p, id);
            known.set(tab.file.path, id);
            known.set(p, id);
            setTabs((prev) => [...prev, tab]);
            setActiveId(id);
            setPathInput(tab.file.path);
          } catch (e) {
            failures.push(`${p}: ${messageOf(e)}`);
          }
        }
      } finally {
        setLoading(false);
      }
      if (failures.length === 1) {
        setError(failures[0]);
      } else if (failures.length > 1) {
        setError(`${failures.length} files could not be opened: ${failures.join(' · ')}`);
      }
    },
    [buildTab],
  );

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

  const patchActive = useCallback((patch: Partial<DocTab>) => {
    const id = activeIdRef.current;
    if (id === null) {
      return;
    }
    setTabs((prev) => prev.map((t) => (t.id === id ? { ...t, ...patch } : t)));
  }, []);

  /** Focus a view in the primary pane; the split pane takes a different one. */
  const focusView = useCallback(
    (v: View) => {
      const id = activeIdRef.current;
      if (id === null) {
        return;
      }
      const cur = tabsRef.current.find((t) => t.id === id);
      if (!cur) {
        return;
      }
      if (!cur.split) {
        setTabs((prev) => prev.map((t) => (t.id === id ? { ...t, view: v } : t)));
        return;
      }
      if (cur.view === v) {
        return;
      }
      // Reassign the other pane so the same view never shows twice.
      const other: View = cur.splitView === v ? cur.view : cur.splitView;
      setTabs((prev) =>
        prev.map((t) => (t.id === id ? { ...t, view: v, splitView: other } : t)),
      );
    },
    [],
  );

  const toggleSplit = useCallback(() => {
    const id = activeIdRef.current;
    if (id === null) {
      return;
    }
    setTabs((prev) =>
      prev.map((t) => {
        if (t.id !== id) {
          return t;
        }
        if (t.split) {
          return { ...t, split: false };
        }
        const second = VIEWS.find((v) => v !== t.view) ?? SPLIT_DEFAULT_SECOND;
        return { ...t, split: true, splitView: second };
      }),
    );
  }, []);

  const setRatio = useCallback((ratio: number) => {
    patchActive({ ratio });
  }, [patchActive]);

  const closeSplit = useCallback(() => {
    patchActive({ split: false });
  }, [patchActive]);

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

  // ---- session: restore on start, autosave on change ----

  const sessionPathRef = useRef<string | null>(null);
  const restoredRef = useRef(false);
  // A session file that failed to load must never be overwritten by the empty
  // autosave state below — that would destroy the only copy of the tab list.
  const sessionBrokenRef = useRef(false);

  const applySelection = useCallback(
    (tab: DocTab, offset: number | null): DocTab => {
      if (offset === null) {
        return tab;
      }
      let found: AsnNode | null = null;
      for (const n of flattenTree(tab.file.root)) {
        if (n.offset === offset) {
          found = n;
        }
      }
      return found ? { ...tab, selected: found } : tab;
    },
    [],
  );

  const restoreSession = useCallback(
    async (announce: boolean) => {
      const sp = await defaultSessionPath();
      sessionPathRef.current = sp;
      if (sp === null) {
        return;
      }
      const res = await loadSessionChecked(sp);
      if (res.reason === 'error') {
        // Not a first run: surface it quietly instead of failing silently, and
        // keep the broken file on disk instead of overwriting it with nothing.
        sessionBrokenRef.current = true;
        setSessionNote(`Session load failed: ${res.message ?? 'unknown error'}`);
        return;
      }
      sessionBrokenRef.current = false;
      const state = res.state;
      if (!state || (state.tabs ?? []).length === 0) {
        return;
      }
      const snap = normalize(state);
      const restored: DocTab[] = [];
      const missing: string[] = [];
      for (const t of snap.tabs) {
        const id = nextId.current;
        nextId.current += 1;
        try {
          const tab = applySelection(await buildTab(t.path, id), t.selectedOffset);
          tab.view = t.view;
          restored.push(tab);
        } catch {
          missing.push(baseName(t.path));
        }
      }
      if (restored.length > 0) {
        setTabs(restored);
        const idx = Math.min(snap.activeIndex, restored.length - 1);
        setActiveId(restored[idx].id);
        setPathInput(restored[idx].file.path);
      }
      if (missing.length > 0) {
        setError(`${missing.length} file(s) from the session are missing: ${missing.join(', ')}`);
      } else if (announce) {
        setSessionNote(`Session restored: ${restored.length} file(s)`);
      }
    },
    [applySelection, buildTab],
  );

  useEffect(() => {
    if (restoredRef.current) {
      return;
    }
    restoredRef.current = true;
    void restoreSession(false);
  }, [restoreSession]);

  // Autosave: debounced ~1s after tabs/view/selection/sidebar change. Errors go
  // to the statusbar (quiet, no banner spam) instead of being swallowed.
  const autosaveRef = useRef<number | null>(null);
  useEffect(() => {
    if (!restoredRef.current) {
      return;
    }
    if (autosaveRef.current !== null) {
      window.clearTimeout(autosaveRef.current);
    }
    autosaveRef.current = window.setTimeout(() => {
      autosaveRef.current = null;
      const sp = sessionPathRef.current;
      if (sp === null || sessionBrokenRef.current) {
        return;
      }
      const cur = tabsRef.current;
      const idx = cur.findIndex((t) => t.id === activeIdRef.current);
      void saveSession(sp, {
        tabs: cur.map((t) => ({
          path: t.file.path,
          view: t.view,
          selectedOffset: t.selected ? t.selected.offset : null,
        })),
        activeIndex: idx < 0 ? 0 : idx,
        sidebarVisible,
      }).then(
        () => setSessionNote(null),
        (e) => setSessionNote(`Session save failed: ${messageOf(e)}`),
      );
    }, 1000);
    return () => {
      if (autosaveRef.current !== null) {
        window.clearTimeout(autosaveRef.current);
        autosaveRef.current = null;
      }
    };
  }, [tabs, sidebarVisible]);

  const saveNow = useCallback(() => {
    void (async () => {
      const sp = sessionPathRef.current ?? (await defaultSessionPath());
      sessionPathRef.current = sp;
      if (sp === null) {
        setSessionNote('Session path unavailable');
        return;
      }
      const cur = tabsRef.current;
      const idx = cur.findIndex((t) => t.id === activeIdRef.current);
      try {
        await saveSession(sp, {
          tabs: cur.map((t) => ({
            path: t.file.path,
            view: t.view,
            selectedOffset: t.selected ? t.selected.offset : null,
          })),
          activeIndex: idx < 0 ? 0 : idx,
          sidebarVisible,
        });
        // An explicit save is an intentional overwrite of a broken file.
        sessionBrokenRef.current = false;
        setSessionNote(`Session saved: ${sp}`);
      } catch (e) {
        setSessionNote(`Session save failed: ${messageOf(e)}`);
      }
    })();
  }, [sidebarVisible]);

  const renderView = useCallback(
    (v: View): ReactNode => {
      if (!active) {
        return <div className="cert-empty">No file open</div>;
      }
      switch (v) {
        case 'hex':
          return <HexView bytes={bytes} selected={selected} onPickOffset={pickOffset} />;
        case 'dump':
          return (
            <DumpPanel
              root={active.file.root}
              selectedOffset={selected?.offset ?? null}
              onSelect={setActiveSelected}
            />
          );
        case 'convert':
          return <ConvertPanel path={active.file.path} label={baseName(active.file.path)} />;
        default:
          return <CertTabContent tab={active} />;
      }
    },
    [active, bytes, selected, pickOffset, setActiveSelected],
  );

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
                  onClick={() => focusView('hex')}
                >
                  Hex · {bytes.length} B
                </button>
                <button
                  role="tab"
                  aria-selected={active.view === 'dump'}
                  className={active.view === 'dump' ? 'tab tab-active' : 'tab'}
                  onClick={() => focusView('dump')}
                >
                  Dump · {nodes.length}
                </button>
                <button
                  role="tab"
                  aria-selected={active.view === 'cert'}
                  className={active.view === 'cert' ? 'tab tab-active' : 'tab'}
                  onClick={() => focusView('cert')}
                >
                  Cert
                </button>
                <button
                  role="tab"
                  aria-selected={active.view === 'convert'}
                  className={active.view === 'convert' ? 'tab tab-active' : 'tab'}
                  onClick={() => focusView('convert')}
                >
                  Convert
                </button>
              </div>
              <div className="pane-head-actions">
                <button
                  className="split-btn"
                  onClick={toggleSplit}
                  title={active.split ? 'Single view' : 'Split view'}
                >
                  {active.split ? '◫ Single' : '◫ Split'}
                </button>
                {active.split && (
                  <>
                    <select
                      className="hash-select"
                      value={active.splitView}
                      onChange={(e) => patchActive({ splitView: e.target.value as View })}
                      aria-label="Second pane view"
                    >
                      {VIEWS.filter((v) => v !== active.view).map((v) => (
                        <option key={v} value={v}>
                          {viewTitle(v)}
                        </option>
                      ))}
                    </select>
                    <button className="split-btn" onClick={closeSplit} title="Close second pane">
                      ✕ Pane
                    </button>
                  </>
                )}
                <button
                  className="split-btn"
                  onClick={() => void restoreSession(true)}
                  title="Restore session from disk"
                >
                  ⟲ Restore
                </button>
              </div>
            </div>
            {active.split ? (
              <SplitLayout
                ratio={active.ratio}
                onRatioChange={setRatio}
                first={(
                  <div className="split-body">
                    <div className="split-cap">{viewTitle(active.view)}</div>
                    {renderView(active.view)}
                  </div>
                )}
                second={(
                  <div className="split-body">
                    <div className="split-cap">{viewTitle(active.splitView)}</div>
                    {renderView(active.splitView)}
                  </div>
                )}
              />
            ) : (
              renderView(active.view)
            )}
            <NodeHashBar path={active.file.path} offset={selected?.offset ?? null} />
          </section>
        )}
      </main>

      <footer className="statusbar">
        <span className="status-sel">
          {selected ? (
            <>
              sel @{selected.offset} · hl={selected.headerLen} · l={selected.length} · total=
              {nodeTotal(selected)} · d={selected.depth} · {selected.tagName} ({selected.tag})
              {selected.oidName ? ` · ${selected.oidName}` : ''}
              {nodeValue(selected) ? ` = ${nodeValue(selected)}` : ''}
            </>
          ) : (
            <>—</>
          )}
        </span>
        <span className="status-right">
          <button className="status-session" onClick={saveNow} title="Save session now">
            {sessionNote ?? 'session'}
          </button>
        </span>
      </footer>
    </div>
  );
}

export default App;
