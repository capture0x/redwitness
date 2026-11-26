"use client";
import { Info } from "lucide-react";
import { Tip } from "./misc";

/** A small (i) icon: hover or focus it to read what a field is for. */
export function InfoTip({ text }: { text: string }) {
  return (
    <Tip label={text}>
      <span tabIndex={0} role="img" aria-label={`Help: ${text}`} data-testid="info-tip" className="inline-flex cursor-help items-center rounded-full text-slate-500 outline-none transition hover:text-indigo-300 focus-visible:text-indigo-300 focus-visible:ring-2 focus-visible:ring-indigo-400/50">
        <Info className="h-3.5 w-3.5" />
      </span>
    </Tip>
  );
}
