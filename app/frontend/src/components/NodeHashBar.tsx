import { useEffect, useState } from 'react';
import { NodeHash } from '../../wailsjs/go/main/App';

const ALGOS = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'] as const;
type Algo = (typeof ALGOS)[number];

interface NodeHashBarProps {
  path: string;
  offset: number | null;
}

export function NodeHashBar({ path, offset }: NodeHashBarProps) {
  const [algo, setAlgo] = useState<Algo>('sha256');
  const [hash, setHash] = useState('');
  const [hashError, setHashError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (offset === null) {
      setHash('');
      setHashError(null);
      setBusy(false);
      return;
    }
    let live = true;
    setBusy(true);
    setHashError(null);
    NodeHash(path, offset, algo).then(
      (h) => {
        if (live) {
          setHash(h);
          setBusy(false);
        }
      },
      (e) => {
        if (live) {
          setHash('');
          setHashError(e instanceof Error ? e.message : String(e));
          setBusy(false);
        }
      },
    );
    return () => {
      live = false;
    };
  }, [path, offset, algo]);

  return (
    <div className="hashbar" aria-label="Node hash">
      <span className="hash-key">{offset === null ? 'hash' : `hash @${offset}`}</span>
      <select
        className="hash-select"
        value={algo}
        onChange={(e) => setAlgo(e.target.value as Algo)}
        aria-label="Hash algorithm"
      >
        {ALGOS.map((a) => (
          <option key={a} value={a}>
            {a}
          </option>
        ))}
      </select>
      {busy ? (
        <span className="hash-busy">…</span>
      ) : hashError ? (
        <span className="hash-err" title={hashError}>
          {hashError}
        </span>
      ) : (
        <span className="hash-val" title={hash}>
          {hash || '—'}
        </span>
      )}
    </div>
  );
}
