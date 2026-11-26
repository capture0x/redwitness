"use client";
import { useSyncExternalStore } from "react";

const PREFIX = "aiveritx.";
const listeners = new Set<() => void>();

function read(key: string): boolean {
  try { return localStorage.getItem(PREFIX + key) === "1"; } catch { return false; }
}
function write(key: string, on: boolean) {
  try { if (on) localStorage.setItem(PREFIX + key, "1"); else localStorage.removeItem(PREFIX + key); } catch { /* private mode: the choice lasts until reload */ }
  listeners.forEach((l) => l());
}
function subscribe(l: () => void) {
  listeners.add(l);
  window.addEventListener("storage", l);
  return () => { listeners.delete(l); window.removeEventListener("storage", l); };
}

/** A per-browser on/off preference. The server snapshot is always false so the first render matches the static HTML. */
export function usePref(key: string) {
  const on = useSyncExternalStore(subscribe, () => read(key), () => false);
  return [on, (v: boolean) => write(key, v)] as const;
}

export const ONBOARDING_DISMISSED = "onboarding-dismissed";
export const ONBOARDING_ACTIVE = "onboarding-active";
export const setPref = write;
export const getPref = read;
