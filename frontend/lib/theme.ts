"use client";
import { useSyncExternalStore } from "react";

/** Colour theme. The choice lives in this browser (localStorage); "system" follows the operating system. Light is the default. */
export type ThemeChoice = "dark" | "light" | "system";
export type Theme = "dark" | "light";
export const THEME_KEY = "aiveritx.theme";
const listeners = new Set<() => void>();
const media = () => (typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: light)") : null);

function readChoice(): ThemeChoice {
  try { const v = localStorage.getItem(THEME_KEY); return v === "dark" || v === "system" ? v : "light"; } catch { return "light"; }
}
function resolve(c: ThemeChoice): Theme { return c === "system" ? (media()?.matches ? "light" : "dark") : c; }
/** Puts the resolved theme on <html> (class + color-scheme). The inline script in app/layout.tsx does the same before first paint. */
function apply() {
  const t = resolve(readChoice());
  const el = document.documentElement;
  el.classList.toggle("light", t === "light");
  el.classList.toggle("dark", t === "dark");
}
export function setTheme(c: ThemeChoice) {
  try { if (c === "light") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, c); } catch { /* private mode: lasts until reload */ }
  apply();
  listeners.forEach((l) => l());
}
function subscribe(l: () => void) {
  const m = media();
  const onSys = () => { apply(); l(); };
  const onStorage = (e: StorageEvent) => { if (e.key === THEME_KEY) { apply(); l(); } };
  listeners.add(l);
  m?.addEventListener("change", onSys);
  window.addEventListener("storage", onStorage);
  return () => { listeners.delete(l); m?.removeEventListener("change", onSys); window.removeEventListener("storage", onStorage); };
}

/** The stored choice (dark / light / system). Server snapshot is "light" so the first render matches the static HTML. */
export function useThemeChoice(): ThemeChoice { return useSyncExternalStore(subscribe, readChoice, () => "light"); }
/** The theme actually shown, for code that needs real colour values (charts, attack tree). */
export function useTheme(): Theme { return useSyncExternalStore(subscribe, () => resolve(readChoice()), () => "light"); }

/** Runs in <head> before the first paint so the page never flashes the wrong theme. Keep in sync with readChoice/resolve. */
export const THEME_BOOT = `(function(){try{var c=localStorage.getItem(${JSON.stringify(THEME_KEY)});var l=!(c==="dark"||(c==="system"&&!matchMedia("(prefers-color-scheme: light)").matches));var e=document.documentElement;e.classList.toggle("light",l);e.classList.toggle("dark",!l)}catch(_){}})()`;
