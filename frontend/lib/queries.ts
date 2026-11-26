"use client";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api } from "./api";

export type LiveEvent = { run_id: string; seq: number; at: number; case_id: string; turn: number; outcome: string; blocked_reason: string | null; tokens: number; replay: boolean; verdict: string | null; confidence: number | null; owasp: string | null };
export type LiveFeed = { live: boolean; runs: number; events: LiveEvent[] };

/** Live agent activity: polls fast while a run is in progress, slowly when idle. */
export function useLiveFeed() {
  return useQuery<LiveFeed, Error>({
    queryKey: ["live"], queryFn: () => api("/live"), placeholderData: keepPreviousData,
    refetchInterval: (q) => (q.state.data?.live ? 1500 : 6000),
  });
}

/** Engine log: the latest steps across ALL runs (the Logs page). */
export function useLogs(limit = 300, paused = false) {
  return useQuery<LiveFeed, Error>({
    queryKey: ["logs", limit], queryFn: () => api(`/live?all_runs=true&limit=${limit}`), placeholderData: keepPreviousData,
    refetchInterval: paused ? false : (q) => (q.state.data?.live ? 1500 : 5000),
  });
}

/** One health sample: API round-trip latency (measured in the browser, real) and counters from /system. */
export type HealthSample = { at: number; latency: number };
export function useHealth() {
  const q = useQuery<{ latency: number; sys: any }, Error>({
    queryKey: ["health"], placeholderData: keepPreviousData, refetchInterval: 3000,
    queryFn: async () => {
      // latency = round trip of a tiny endpoint (not /system, which also verifies the whole audit chain)
      const t = performance.now(); await api("/auth/status"); const latency = Math.round(performance.now() - t);
      return { latency, sys: await api("/system") };
    },
  });
  const [history, setHistory] = useState<number[]>([]);
  useEffect(() => { if (q.data) setHistory((h) => [...h.slice(-29), q.data!.latency]); }, [q.dataUpdatedAt]); // eslint-disable-line react-hooks/exhaustive-deps
  return { ...q, history };
}

/** Token burn rate (tokens/min) derived from consecutive samples of the cumulative token counter. */
export function useTokenRate(totalTokens: number | undefined, stamp: number) {
  const last = useRef<{ t: number; n: number } | null>(null);
  const [rate, setRate] = useState<number[]>([]);
  useEffect(() => {
    if (totalTokens == null) return;
    const now = Date.now();
    if (last.current && now - last.current.t >= 1000) {
      const perMin = Math.max(0, ((totalTokens - last.current.n) / (now - last.current.t)) * 60000);
      setRate((r) => [...r.slice(-29), Math.round(perMin)]);
    }
    last.current = { t: now, n: totalTokens };
  }, [stamp]); // eslint-disable-line react-hooks/exhaustive-deps
  return rate;
}
