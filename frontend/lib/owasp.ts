import { CircleDashed, Eye, Loader, ShieldAlert, ShieldCheck, type LucideIcon } from "lucide-react";

export type OwaspStatus = "not_tested" | "testing" | "vulnerable" | "review" | "clean";

/** Status → label, tone, icon and card styling (ring/glow/accent are deliberately more pronounced than the old flat cards). */
export const OWASP_STATUS: Record<OwaspStatus, { label: string; tone: "neutral" | "blue" | "red" | "amber" | "green"; ring: string; glow: string; dot: string; bar: string; icon: LucideIcon; text: string; wash: string }> = {
  not_tested: { label: "Not tested", tone: "neutral", ring: "border-white/[0.08]", glow: "", dot: "bg-slate-500", bar: "bg-slate-600/60", icon: CircleDashed, text: "text-slate-400", wash: "from-slate-400/[0.05]" },
  testing: { label: "Testing", tone: "blue", ring: "border-sky-400/45", glow: "shadow-[0_0_36px_-10px_rgba(56,189,248,.6)]", dot: "bg-sky-400 animate-pulse", bar: "bg-sky-400 animate-pulse", icon: Loader, text: "text-sky-300", wash: "from-sky-400/[0.10]" },
  vulnerable: { label: "Vulnerable", tone: "red", ring: "border-rose-400/45", glow: "shadow-[0_0_36px_-10px_rgba(244,63,94,.65)]", dot: "bg-rose-500", bar: "bg-rose-500", icon: ShieldAlert, text: "text-rose-300", wash: "from-rose-400/[0.11]" },
  review: { label: "Needs review", tone: "amber", ring: "border-amber-400/45", glow: "shadow-[0_0_36px_-12px_rgba(251,191,36,.55)]", dot: "bg-amber-400", bar: "bg-amber-400", icon: Eye, text: "text-amber-300", wash: "from-amber-400/[0.10]" },
  clean: { label: "Clean", tone: "green", ring: "border-emerald-400/40", glow: "shadow-[0_0_36px_-12px_rgba(52,211,153,.55)]", dot: "bg-emerald-400", bar: "bg-emerald-400", icon: ShieldCheck, text: "text-emerald-300", wash: "from-emerald-400/[0.09]" },
};

export const OWASP_DISCLAIMER =
  "This view maps behavioral quality probes made through a black-box API to the categories of the OWASP Top 10 for LLM Applications (2025); it is not a compliance certificate. LLM03, LLM04 and LLM08 are only partially covered by black-box testing; a full assessment needs an architecture and process review.";

export const owasp_short = (id?: string | null) => (id ? id.split("_")[0] : "");
