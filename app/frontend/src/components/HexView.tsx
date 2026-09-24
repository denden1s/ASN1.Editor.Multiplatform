import { useEffect, useMemo, useState } from 'react';
import type { AsnNode } from '../asn1';
import { nodeTotal } from '../asn1';

const PAGE_BYTES = 4096;
const ROW = 16;

interface HexViewProps {
  bytes: Uint8Array;
  selected: AsnNode | null;
  onPickOffset: (byteOffset: number) => void;
}

export function HexView({ bytes, selected, onPickOffset }: HexViewProps) {
  const pageCount = Math.max(1, Math.ceil(bytes.length / PAGE_BYTES));
  const [page, setPage] = useState(0);

  const selStart = selected?.offset ?? -1;
  const selEnd = selected ? selected.offset + nodeTotal(selected) : -1;
  const selHeaderEnd = selected ? selected.offset + selected.headerLen : -1;

  useEffect(() => {
    setPage(0);
  }, [bytes]);

  useEffect(() => {
    if (!selected) {
      return;
    }
    const p = Math.floor(selected.offset / PAGE_BYTES);
    setPage((prev) => (prev === p ? prev : p));
  }, [selected]);

  useEffect(() => {
    if (selStart < 0) {
      return;
    }
    document.querySelector(`[data-bo="${selStart}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [selStart, page]);

  const start = Math.min(page, pageCount - 1) * PAGE_BYTES;
  const end = Math.min(start + PAGE_BYTES, bytes.length);

  const rows = useMemo(() => {
    const out: number[] = [];
    for (let r = start; r < end; r += ROW) {
      out.push(r);
    }
    return out;
  }, [start, end]);

  return (
    <div className="hexwrap">
      <div className="hexpager">
        <button className="pager-btn" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
          ‹ Prev
        </button>
        <span className="pager-label">
          0x{start.toString(16).padStart(8, '0')} – 0x
          {Math.max(0, end - 1)
            .toString(16)
            .padStart(8, '0')}{' '}
          · page {Math.min(page, pageCount - 1) + 1}/{pageCount}
        </span>
        <button
          className="pager-btn"
          disabled={page >= pageCount - 1}
          onClick={() => setPage((p) => p + 1)}
        >
          Next ›
        </button>
      </div>
      <div className="hexgrid" role="grid" aria-label="Hex view">
        {rows.map((r) => (
          <div className="hexrow" key={r}>
            <span className="hexoff">{r.toString(16).padStart(8, '0')}</span>
            <span className="hexbytes">
              {Array.from({ length: Math.min(ROW, bytes.length - r) }, (_, i) => {
                const idx = r + i;
                const inRange = idx >= selStart && idx < selEnd;
                const cls = inRange ? (idx < selHeaderEnd ? 'hbyte hsel hhead' : 'hbyte hsel') : 'hbyte';
                return (
                  <span key={idx} data-bo={idx} className={cls} onClick={() => onPickOffset(idx)}>
                    {bytes[idx].toString(16).padStart(2, '0')}
                  </span>
                );
              })}
            </span>
            <span className="hexascii">{asciiOf(bytes, r)}</span>
          </div>
        ))}
        {bytes.length === 0 && <div className="loading-note">No bytes to show.</div>}
      </div>
    </div>
  );
}

function asciiOf(bytes: Uint8Array, rowStart: number): string {
  let s = '';
  const end = Math.min(rowStart + ROW, bytes.length);
  for (let i = rowStart; i < end; i++) {
    const b = bytes[i];
    s += b >= 32 && b <= 126 ? String.fromCharCode(b) : '·';
  }
  return s;
}
