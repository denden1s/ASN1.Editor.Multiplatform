import { GetHex } from '../wailsjs/go/main/App';
import type { certview, main, session } from '../wailsjs/go/models';

export type AsnNode = main.NodeDTO;
export type AsnFile = main.FileView;
export type AsnCert = certview.Cert;
export type AsnReq = certview.Req;
export type AsnSession = session.State;

/** Detail views persisted in the session. */
export const VIEWS = ['hex', 'dump', 'cert', 'convert'] as const;
export type View = (typeof VIEWS)[number];

export function isView(v: unknown): v is View {
  return typeof v === 'string' && (VIEWS as readonly string[]).includes(v);
}

/** Full byte length of a node: header + content. */
export function nodeTotal(n: AsnNode): number {
  return n.headerLen + n.length;
}

/** Children, tolerating null leaves from the backend. */
export function childNodes(n: AsnNode): AsnNode[] {
  return n.children ?? [];
}

/** Decoded value text; empty for constructed/context nodes. Never undefined. */
export function nodeValue(n: AsnNode): string {
  return n.value ?? '';
}

/** Pre-order flatten (iterative, safe for deep trees). */
export function flattenTree(root: AsnNode): AsnNode[] {
  const out: AsnNode[] = [];
  const stack: AsnNode[] = [root];
  while (stack.length > 0) {
    const n = stack.pop() as AsnNode;
    out.push(n);
    const kids = childNodes(n);
    for (let i = kids.length - 1; i >= 0; i--) {
      stack.push(kids[i]);
    }
  }
  return out;
}

/** Deepest node whose [offset, offset + total) range covers a byte. */
export function findDeepest(root: AsnNode, byteOffset: number): AsnNode | null {
  let best: AsnNode | null = null;
  const stack: AsnNode[] = [root];
  while (stack.length > 0) {
    const n = stack.pop() as AsnNode;
    if (byteOffset >= n.offset && byteOffset < n.offset + nodeTotal(n)) {
      if (!best || n.depth > best.depth) {
        best = n;
      }
      for (const k of childNodes(n)) {
        stack.push(k);
      }
    }
  }
  return best;
}

/** Parse lowercase hex without spaces into bytes (bad pairs become 0). */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) {
    const v = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    out[i] = Number.isNaN(v) ? 0 : v;
  }
  return out;
}

const HEX_CHUNK = 256 * 1024; // bytes per GetHex call, well under the 1MB limit

/** Fetch the full DER range, chunked so large files stay under the backend limit. */
export async function fetchFullHex(path: string, total: number): Promise<string> {
  if (total <= 0) {
    return '';
  }
  const parts: string[] = [];
  for (let off = 0; off < total; off += HEX_CHUNK) {
    parts.push(await GetHex(path, off, Math.min(HEX_CHUNK, total - off)));
  }
  return parts.join('');
}

/**
 * One asn1parse-style line per node:
 * `offset : d=depth hl=headerLen l=length : indent [cons:] tagName [: oid] [: value]`
 */
export function formatDumpLine(n: AsnNode): string {
  const off = String(n.offset).padStart(6, ' ');
  const len = String(n.length).padStart(6, ' ');
  const indent = '  '.repeat(Math.max(0, n.depth));
  const cons = n.hasChildren ? 'cons: ' : '';
  const oid = n.oidName ? ` : ${n.oidName}` : '';
  const v = nodeValue(n);
  const val = v ? ` : ${v}` : '';
  return `${off}  d=${n.depth}  hl=${n.headerLen}  l=${len}  ${indent}${cons}${n.tagName}${oid}${val}`;
}
