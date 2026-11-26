"use client";
import { useRef, useState } from "react";
import { UploadCloud } from "lucide-react";
import { cn } from "@/lib/utils";

/** Drag-and-drop file area (also opens the file picker on click or Enter). Extension-checked on the client; the server validates again. */
export default function Dropzone({ accept, onFile, title, hint, disabled, busy, testId, className }: {
  accept: string[]; onFile: (f: File) => void; title: string; hint?: string; disabled?: boolean; busy?: boolean; testId?: string; className?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [bad, setBad] = useState("");
  const take = (f?: File) => {
    if (!f) return;
    if (!accept.some((a) => f.name.toLowerCase().endsWith(a))) { setBad(`Unsupported file. Accepted: ${accept.join(", ")}`); return; }
    setBad(""); onFile(f);
  };
  return (
    <div className={className}>
      <div role="button" tabIndex={disabled ? -1 : 0} aria-disabled={disabled} data-testid={testId}
        onClick={() => !disabled && input.current?.click()} onKeyDown={(e) => { if ((e.key === "Enter" || e.key === " ") && !disabled) { e.preventDefault(); input.current?.click(); } }}
        onDragOver={(e) => { e.preventDefault(); if (!disabled) setOver(true); }} onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); if (!disabled) take(e.dataTransfer.files?.[0]); }}
        className={cn("group relative flex cursor-pointer flex-col items-center justify-center gap-2 overflow-hidden rounded-2xl border-2 border-dashed px-6 py-9 text-center transition",
          over ? "border-violet-400/80 bg-violet-500/15 shadow-glow" : "border-white/15 bg-white/[0.03] hover:border-violet-400/50 hover:bg-violet-500/[0.07]", disabled && "cursor-not-allowed opacity-50")}>
        <div className={cn("grid h-12 w-12 place-items-center rounded-2xl bg-gradient-to-br from-violet-500/30 to-blue-500/20 text-violet-200 transition", over && "scale-110", busy && "animate-pulse")}><UploadCloud className="h-6 w-6" /></div>
        <div className="text-[15px] font-semibold text-white">{busy ? "Working…" : title}</div>
        <div className="text-xs text-slate-400">{hint || `Drag a file here or click to browse · ${accept.join(" ")}`}</div>
        <input ref={input} type="file" accept={accept.join(",")} className="hidden" onChange={(e) => { take(e.target.files?.[0]); e.target.value = ""; }} />
      </div>
      {bad && <div className="mt-2 text-xs text-red-400" role="alert">{bad}</div>}
    </div>
  );
}
