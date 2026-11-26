"use client";
import { Monitor, Moon, Sun } from "lucide-react";
import { cn } from "@/lib/utils";
import { setTheme, useThemeChoice, type ThemeChoice } from "@/lib/theme";

const OPTIONS: { id: ThemeChoice; label: string; icon: typeof Sun }[] = [
  { id: "light", label: "Light", icon: Sun },
  { id: "dark", label: "Dark", icon: Moon },
  { id: "system", label: "System", icon: Monitor },
];

/** Three-way theme switch (Light / Dark / System). Light is the default. The choice is remembered in this browser. */
export default function ThemeToggle({ className }: { className?: string }) {
  const choice = useThemeChoice();
  return (
    <div role="radiogroup" aria-label="Colour theme" data-testid="theme-toggle" className={cn("grid grid-cols-3 gap-0.5 rounded-lg border border-white/[0.06] bg-white/[0.02] p-0.5", className)}>
      {OPTIONS.map(({ id, label, icon: Icon }) => {
        const on = choice === id;
        return (
          <button key={id} type="button" role="radio" aria-checked={on} title={`${label} theme`} data-testid={`theme-${id}`} onClick={() => setTheme(id)}
            className={cn("flex h-7 items-center justify-center gap-1.5 rounded-md text-[11px] font-medium transition-colors",
              on ? "bg-white/[0.08] text-slate-100 shadow-sm" : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-300")}>
            <Icon className="h-3.5 w-3.5" />{label}
          </button>
        );
      })}
    </div>
  );
}
