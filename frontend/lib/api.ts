"use client";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useCallback } from "react";

import { friendlyError, NETWORK_ERROR } from "./friendly";

export class ApiError extends Error {
  constructor(public status: number, public reason: string | null, message: string, public raw: string = message) { super(message); }
}

export async function api<T = any>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method || "GET").toUpperCase();
  let r: Response;
  try {
    r = await fetch(`/api${path}`, {
      ...init, credentials: "same-origin",
      headers: { "content-type": "application/json", ...(method !== "GET" ? { "x-aiveritx-csrf": "1" } : {}), ...(init?.headers || {}) },
    });
  } catch { throw new ApiError(0, "NETWORK", NETWORK_ERROR); }
  const text = await r.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* plain text */ }
  if (!r.ok) {
    const d = data?.detail;
    const msg = typeof d === "string" ? d : d?.message || (Array.isArray(d) ? d.map((x: any) => x.msg).join("; ") : text) || `HTTP ${r.status}`;
    if (r.status === 401 && typeof window !== "undefined" && !path.startsWith("/auth/")) window.dispatchEvent(new Event("aiveritx:unauthorized"));
    throw new ApiError(r.status, d?.reason ?? null, path.startsWith("/auth/") ? msg : friendlyError(r.status, d?.reason ?? null, msg), msg);
  }
  return data as T;
}

/**
 * Polls `fn` every `ms` (once if ms=0) on top of TanStack Query: identical polls are de-duplicated across components,
 * the previous data stays on screen while a refetch (or a filter change) is in flight, so the UI never blanks or freezes.
 * `deps` must contain every variable the closure reads (they become part of the cache key).
 */
export function usePoll<T>(fn: () => Promise<T>, ms = 3000, deps: any[] = []) {
  const q = useQuery<T, Error>({
    queryKey: ["poll", fn.toString(), ...deps],
    queryFn: () => fn(),
    refetchInterval: ms || false,
    placeholderData: keepPreviousData,
  });
  const reload = useCallback(async () => { await q.refetch(); }, [q.refetch]); // eslint-disable-line react-hooks/exhaustive-deps
  return { data: (q.data ?? null) as T | null, error: q.error ? q.error.message : null, loading: q.isPending, fetching: q.isFetching, updatedAt: q.dataUpdatedAt, reload };
}

export const fmtDate = (v: string | number | null | undefined) => {
  if (v == null) return "-";
  const d = typeof v === "number" ? new Date(v * 1000) : new Date(v);
  return d.toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
};
export const fmtNum = (n: number | null | undefined) => (n ?? 0).toLocaleString("en-US");
export async function sha256Hex(buf: ArrayBuffer) {
  const h = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(h)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
export const sevLabel = (s: string) => ({ critical: "Critical Risk", high: "High Risk", medium: "Medium Risk", low: "Low Risk", info: "Info" } as any)[s] || s;

export function timeAgo(v: number | string | null | undefined) {
  if (v == null) return "-";
  const t = typeof v === "number" ? v * 1000 : new Date(v).getTime();
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const fmtCompact = (n: number | null | undefined) => new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n ?? 0);
