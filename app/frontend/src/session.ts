import { DefaultSessionPath, LoadSession, SaveSession } from '../wailsjs/go/main/App';
import { session } from '../wailsjs/go/models';
import { isView } from './asn1';
import type { AsnSession, View } from './asn1';

export interface SessionTab {
  path: string;
  view: View;
  selectedOffset: number | null;
}

export interface SessionSnapshot {
  tabs: SessionTab[];
  activeIndex: number;
  sidebarVisible: boolean;
}

const VERSION = 1;

/** Go reports a missing file as "no such file or directory" on every OS. */
export function isNotExist(msg: string): boolean {
  return /no such file or directory|not exist/i.test(msg);
}

/** Default session path, or null when the runtime is unavailable. */
export async function defaultSessionPath(): Promise<string | null> {
  try {
    return await DefaultSessionPath();
  } catch {
    return null;
  }
}

/** Load a session; reports 'missing' on first run (os.ErrNotExist). */
export async function loadSessionChecked(
  path: string,
): Promise<{ state: AsnSession | null; reason: 'ok' | 'missing' | 'error'; message?: string }> {
  try {
    return { state: await LoadSession(path), reason: 'ok' };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { state: null, reason: isNotExist(msg) ? 'missing' : 'error', message: msg };
  }
}

/** Persist the session; throws so the caller can surface it. */
export async function saveSession(path: string, snap: SessionSnapshot): Promise<void> {
  const state = session.State.createFrom({
    version: VERSION,
    tabs: snap.tabs.map((t) => ({
      path: t.path,
      view: t.view,
      selectedOffset: t.selectedOffset ?? undefined,
    })),
    activeIndex: snap.activeIndex,
    sidebarVisible: snap.sidebarVisible,
  });
  await SaveSession(path, state);
}

/** Normalize a loaded state into snapshot shape, dropping junk entries. */
export function normalize(state: AsnSession): SessionSnapshot {
  const tabs: SessionTab[] = [];
  for (const t of state?.tabs ?? []) {
    if (!t || typeof t.path !== 'string' || t.path === '') {
      continue;
    }
    const offset =
      typeof t.selectedOffset === 'number' && Number.isFinite(t.selectedOffset)
        ? t.selectedOffset
        : null;
    tabs.push({ path: t.path, view: isView(t.view) ? t.view : 'hex', selectedOffset: offset });
  }
  const raw = typeof state?.activeIndex === 'number' ? state.activeIndex : 0;
  const activeIndex = tabs.length === 0 ? 0 : Math.min(Math.max(0, raw), tabs.length - 1);
  return {
    tabs,
    activeIndex,
    sidebarVisible: state?.sidebarVisible !== false,
  };
}