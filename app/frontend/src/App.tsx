import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { OpenFile } from '../wailsjs/go/main/App';
import { OnFileDrop, OnFileDropOff } from '../wailsjs/runtime/runtime';
import { DumpPanel } from './components/DumpPanel';
import { HexView } from './components/HexView';
import { TreeView } from './components/TreeView';
import { fetchFullHex, findDeepest, flattenTree, hexToBytes, nodeTotal } from './asn1';
import type { AsnFile, AsnNode } from './asn1';

type Tab = 'hex' | 'dump';

function messageOf(e: unknown): string {
  if (e instanceof Error) {
    return e.message;
  }
  return String(e);
}

function App() {
  const [pathInput, setPathInput] = useState('');
  const [file, setFile] = useState<AsnFile | null>(null);
  const [hex, setHex] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AsnNode | null>(null);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const [tab, setTab] = useState<Tab>('hex');

  const openPath = useCallback(async (raw: string) => {
    const p = raw.trim();
    if (!p) {
      setError('Enter a file path first.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const fv = await OpenFile(p);
      const total = fv.root.headerLen + fv.root.length;
      const full = await fetchFullHex(fv.path, total);
      setFile(fv);
      setHex(full);
      setSelected(fv.root);
      setCollapsed(new Set());
      setTab('hex');
      setPathInput(fv.path);
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setLoading(false);
    }
  }, []);

  // Drag-and-drop onto the window (Wails runtime). Plain browsers have no
  // runtime — the path input above stays the working fallback.
  const openRef = useRef(openPath);
  openRef.current = openPath;
  useEffect(() => {
    try {
      OnFileDrop((_x, _y, paths) => {
        if (paths && paths.length > 0) {
          void openRef.current(paths[0]);
        }
      }, true);
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

  const toggle = useCallback((offset: number) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(offset)) {
        next.delete(offset);
      } else {
        next.add(offset);
      }
      return next;
    });
  }, []);

  const pickOffset = useCallback(
    (off: number) => {
      if (!file) {
        return;
      }
      const n = findDeepest(file.root, off);
      if (n) {
        setSelected(n);
      }
    },
    [file],
  );

  const bytes = useMemo(() => hexToBytes(hex), [hex]);
  const nodes = useMemo(() => (file ? flattenTree(file.root) : []), [file]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">◈</span>
          <span>ASN.1 Viewer</span>
        </div>
        <form
          className="openform"
          onSubmit={(e) => {
            e.preventDefault();
            void openPath(pathInput);
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
        {file && (
          <div className="filemeta">
            {file.typeHint ? (
              <span className="badge">{file.typeHint}</span>
            ) : (
              <span className="badge badge-dim">untyped</span>
            )}
            <span className="chip">{file.encoding || 'DER'}</span>
            {file.label && (
              <span className="chip" title={file.label}>
                {file.label}
              </span>
            )}
          </div>
        )}
      </header>

      {file && (
        <div className="filepath" title={file.path}>
          {file.path}
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

      {!file ? (
        <main className="empty">
          <div className="empty-h">No file open</div>
          <p className="empty-p">
            Type a path above and press Enter, or drop a DER / PEM / HEX / Base64 file onto this
            window.
          </p>
        </main>
      ) : (
        <main className="workspace">
          <section className="pane tree-pane" aria-label="Structure">
            <div className="pane-head">
              <span className="pane-title">Structure</span>
              <span className="pane-sub">{nodes.length} nodes</span>
            </div>
            <TreeView
              root={file.root}
              selectedOffset={selected?.offset ?? null}
              collapsed={collapsed}
              onSelect={setSelected}
              onToggle={toggle}
            />
          </section>
          <section className="pane detail-pane" aria-label="Details">
            <div className="pane-head">
              <div className="tabs" role="tablist">
                <button
                  role="tab"
                  aria-selected={tab === 'hex'}
                  className={tab === 'hex' ? 'tab tab-active' : 'tab'}
                  onClick={() => setTab('hex')}
                >
                  Hex · {bytes.length} B
                </button>
                <button
                  role="tab"
                  aria-selected={tab === 'dump'}
                  className={tab === 'dump' ? 'tab tab-active' : 'tab'}
                  onClick={() => setTab('dump')}
                >
                  Dump · {nodes.length}
                </button>
              </div>
            </div>
            {tab === 'hex' ? (
              <HexView bytes={bytes} selected={selected} onPickOffset={pickOffset} />
            ) : (
              <DumpPanel
                root={file.root}
                selectedOffset={selected?.offset ?? null}
                onSelect={setSelected}
              />
            )}
          </section>
        </main>
      )}

      <footer className="statusbar">
        {selected ? (
          <span>
            sel @{selected.offset} · hl={selected.headerLen} · l={selected.length} · total=
            {nodeTotal(selected)} · d={selected.depth} · {selected.tagName} ({selected.tag})
            {selected.oidName ? ` · ${selected.oidName}` : ''}
          </span>
        ) : (
          <span>—</span>
        )}
      </footer>
    </div>
  );
}

export default App;
