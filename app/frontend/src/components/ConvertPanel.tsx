import { useCallback, useEffect, useState } from 'react';
import { Convert, ConvertText } from '../../wailsjs/go/main/App';

type Format = 'pem' | 'hex' | 'base64';

const FORMATS: Format[] = ['pem', 'hex', 'base64'];

interface ConvertPanelProps {
  path: string;
  label: string;
}

/** Copy with a fallback for WebViews without the async clipboard API. */
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the textarea path */
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

export function ConvertPanel({ path, label }: ConvertPanelProps) {
  // Export
  const [to, setTo] = useState<Format>('pem');
  const [exportText, setExportText] = useState('');
  const [exportErr, setExportErr] = useState<string | null>(null);
  const [exportBusy, setExportBusy] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  // Import
  const [from, setFrom] = useState<Format>('pem');
  const [inputText, setInputText] = useState('');
  const [importText, setImportText] = useState('');
  const [importErr, setImportErr] = useState<string | null>(null);
  const [importBusy, setImportBusy] = useState(false);

  useEffect(() => {
    setExportText('');
    setExportErr(null);
  }, [path]);

  const runExport = useCallback(async () => {
    setExportBusy(true);
    setExportErr(null);
    try {
      setExportText(await Convert(path, to));
    } catch (e) {
      setExportText('');
      setExportErr(e instanceof Error ? e.message : String(e));
    } finally {
      setExportBusy(false);
    }
  }, [path, to]);

  const runImport = useCallback(async () => {
    setImportBusy(true);
    setImportErr(null);
    try {
      setImportText(await ConvertText(inputText, from, to));
    } catch (e) {
      setImportText('');
      setImportErr(e instanceof Error ? e.message : String(e));
    } finally {
      setImportBusy(false);
    }
  }, [inputText, from, to]);

  const onCopy = useCallback(async (which: string) => {
    const ok = await copyText(which === 'export' ? exportText : importText);
    setCopied(ok ? which : null);
  }, [exportText, importText]);

  useEffect(() => {
    if (copied === null) {
      return;
    }
    const id = window.setTimeout(() => setCopied(null), 1200);
    return () => window.clearTimeout(id);
  }, [copied]);

  return (
    <div className="convert" aria-label="Format converter">
      <section className="cv-sec">
        <div className="cv-sec-h">
          <span>Export · {label}</span>
          <span className="cv-actions">
            <label className="cv-label">
              To
              <select
                className="hash-select"
                value={to}
                onChange={(e) => setTo(e.target.value as Format)}
              >
                {FORMATS.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
            </label>
            <button className="cv-btn" onClick={() => void runExport()} disabled={exportBusy}>
              {exportBusy ? 'Converting…' : 'Convert'}
            </button>
            <button
              className="cv-btn"
              onClick={() => void onCopy('export')}
              disabled={!exportText}
            >
              {copied === 'export' ? 'Copied' : 'Copy'}
            </button>
          </span>
        </div>
        <Result text={exportText} error={exportErr} wrap={to !== 'hex'} />
      </section>

      <section className="cv-sec">
        <div className="cv-sec-h">
          <span>Import</span>
          <span className="cv-actions">
            <label className="cv-label">
              From
              <select
                className="hash-select"
                value={from}
                onChange={(e) => setFrom(e.target.value as Format)}
              >
                {FORMATS.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
            </label>
            <button className="cv-btn" onClick={() => void runImport()} disabled={importBusy}>
              {importBusy ? 'Converting…' : 'Convert'}
            </button>
            <button
              className="cv-btn"
              onClick={() => void onCopy('import')}
              disabled={!importText}
            >
              {copied === 'import' ? 'Copied' : 'Copy'}
            </button>
          </span>
        </div>
        <textarea
          className="cv-input"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Paste PEM, Hex or Base64 here"
          spellCheck={false}
          aria-label="Text to convert"
        />
        <Result text={importText} error={importErr} wrap={to !== 'hex'} />
      </section>
    </div>
  );
}

function Result({ text, error, wrap }: { text: string; error: string | null; wrap: boolean }) {
  if (error) {
    return (
      <div className="cv-err" role="alert">
        {error}
      </div>
    );
  }
  if (!text) {
    return <div className="cv-note">No result yet.</div>;
  }
  const lines = text.split('\n').length;
  const bytes = text.replace(/\s+/g, '').length;
  return (
    <>
      <div className="cv-note">
        {lines} lines · {bytes} chars
      </div>
      <pre className={wrap ? 'cv-out cv-out-wrap' : 'cv-out cv-out-nowrap'}>{text}</pre>
    </>
  );
}