import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';

interface SplitLayoutProps {
  ratio: number;
  onRatioChange: (ratio: number) => void;
  first: ReactNode;
  second: ReactNode;
}

const MIN_RATIO = 0.2;
const MAX_RATIO = 0.8;

function clamp(r: number): number {
  if (!Number.isFinite(r)) {
    return 0.5;
  }
  return Math.min(MAX_RATIO, Math.max(MIN_RATIO, r));
}

/**
 * Two panes split by a draggable divider. Both panes share the same document,
 * so the ratio lives with the file tab that owns them.
 */
export function SplitLayout({ ratio, onRatioChange, first, second }: SplitLayoutProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [dragging, setDragging] = useState(false);

  const onPointerDown = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(true);
  }, []);

  useEffect(() => {
    if (!dragging) {
      return;
    }
    const move = (ev: PointerEvent) => {
      const host = hostRef.current;
      if (!host) {
        return;
      }
      const rect = host.getBoundingClientRect();
      if (rect.width === 0) {
        return;
      }
      onRatioChange(clamp((ev.clientX - rect.left) / rect.width));
    };
    const up = () => setDragging(false);
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    window.addEventListener('pointercancel', up);
    return () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
    };
  }, [dragging, onRatioChange]);

  const pct = `${clamp(ratio) * 100}%`;

  return (
    <div
      ref={hostRef}
      className={dragging ? 'split split-dragging' : 'split'}
      style={{ gridTemplateColumns: `${pct} 6px 1fr` }}
    >
      <div className="split-pane">{first}</div>
      <div
        className="split-divider"
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize panes"
        tabIndex={0}
        onPointerDown={onPointerDown}
        onKeyDown={(e) => {
          if (e.key === 'ArrowLeft') {
            onRatioChange(clamp(clamp(ratio) - 0.02));
          }
          if (e.key === 'ArrowRight') {
            onRatioChange(clamp(clamp(ratio) + 0.02));
          }
        }}
        title="Drag to resize"
      >
        <span className="split-grip" />
      </div>
      <div className="split-pane">{second}</div>
    </div>
  );
}