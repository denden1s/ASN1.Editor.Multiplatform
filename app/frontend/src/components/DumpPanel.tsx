import { useEffect, useMemo } from 'react';
import type { AsnNode } from '../asn1';
import { flattenTree, formatDumpLine } from '../asn1';

interface DumpPanelProps {
  root: AsnNode;
  selectedOffset: number | null;
  onSelect: (node: AsnNode) => void;
}

export function DumpPanel({ root, selectedOffset, onSelect }: DumpPanelProps) {
  const nodes = useMemo(() => flattenTree(root), [root]);

  useEffect(() => {
    if (selectedOffset === null) {
      return;
    }
    document.querySelector(`[data-dump="${selectedOffset}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [selectedOffset]);

  return (
    <div className="dump" aria-label="asn1parse dump">
      {nodes.map((n) => (
        <button
          key={n.offset}
          data-dump={n.offset}
          className={n.offset === selectedOffset ? 'dline dline-selected' : 'dline'}
          onClick={() => onSelect(n)}
          title={`${n.tag} · offset ${n.offset}`}
        >
          {formatDumpLine(n)}
        </button>
      ))}
    </div>
  );
}
