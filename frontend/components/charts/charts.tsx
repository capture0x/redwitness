"use client";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { OWASP_STATUS, OwaspStatus } from "@/lib/owasp";
import { cn } from "@/lib/utils";
import { useTheme } from "@/lib/theme";

const tip = {
  // HTML tooltip: CSS variables follow the dark/light theme directly
  contentStyle: { background: "rgb(var(--c-panel) / .96)", border: "1px solid rgb(var(--c-white) / .1)", borderRadius: 10, fontSize: 12, color: "rgb(var(--c-slate-200))", boxShadow: "var(--sh-glass)", padding: "8px 12px" },
  labelStyle: { color: "rgb(var(--c-slate-400))", marginBottom: 2 }, itemStyle: { padding: 0 }, cursor: { stroke: "rgba(165,166,251,.35)", strokeDasharray: "3 3" },
};
export const SEV_COLOR: Record<string, string> = { critical: "#f43f5e", high: "#fb923c", medium: "#fbbf24", low: "#38bdf8", info: "#94a3b8" };
/** SVG colours (grid, ticks, dot centres, hover bands) per theme: Recharts writes them as attributes, so they are picked in JS. */
const UI = {
  dark: { grid: "rgba(255,255,255,.05)", polar: "rgba(255,255,255,.08)", tick: "#64748b", label: "#94a3b8", dot: "#0a0b11", band: "rgba(255,255,255,.04)" },
  light: { grid: "rgba(16,18,27,.08)", polar: "rgba(16,18,27,.12)", tick: "#71717a", label: "#52525b", dot: "#ffffff", band: "rgba(16,18,27,.045)" },
};
const useUi = () => UI[useTheme()];
const axisOf = (ui: typeof UI.dark) => ({ tick: { fill: ui.tick, fontSize: 11 }, tickLine: false as const, axisLine: false as const });

/** A single data point cannot draw a trend: prepend a zero baseline so the area/line is still visible. */
const pad = <T extends Record<string, any>>(data: T[], zero: Partial<T>): T[] => (data.length === 1 ? [{ ...data[0], ...zero, day: "" } as T, ...data] : data);

const Empty = ({ text, h = 220 }: { text: string; h?: number }) => <div className="flex items-center justify-center text-sm text-slate-500" style={{ height: h }}>{text}</div>;

/** Token usage per day - smooth area with a soft indigo gradient. */
export function TokenArea({ data, height = 240 }: { data: { day: string; tokens: number }[]; height?: number }) {
  const ui = useUi(); const axis = axisOf(ui);
  if (!data.length) return <Empty text="No token usage yet." h={height} />;
  const d = pad(data, { tokens: 0 });
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={d} margin={{ left: -8, right: 8, top: 8 }}>
        <defs><linearGradient id="tk" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#818cf8" stopOpacity={0.4} /><stop offset="100%" stopColor="#818cf8" stopOpacity={0} /></linearGradient></defs>
        <CartesianGrid stroke={ui.grid} vertical={false} />
        <XAxis dataKey="day" {...axis} /><YAxis {...axis} width={44} tickFormatter={(v) => (v >= 1000 ? `${Math.round(v / 1000)}k` : v)} />
        <Tooltip {...tip} formatter={(v: any) => [Number(v).toLocaleString("en-US"), "tokens"]} />
        <Area type="monotone" dataKey="tokens" stroke="#a5a6fb" strokeWidth={2} fill="url(#tk)" dot={{ r: 3, fill: ui.dot, stroke: "#a5a6fb", strokeWidth: 2 }} activeDot={{ r: 5, fill: "#a5a6fb" }} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function PassTip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  if (!p.n) return null;
  return (
    <div className="rounded-xl border border-white/10 bg-panel/95 px-3.5 py-3 text-xs shadow-[0_18px_40px_-14px_rgba(0,0,0,.85),0_0_26px_-8px_rgba(52,211,153,.5)] backdrop-blur">
      <div className="mb-1.5 text-[11px] text-slate-400">{label}</div>
      <div className="flex items-baseline gap-2"><span className="text-[22px] font-bold leading-none text-emerald-300 tabular">{p.rate}%</span><span className="text-slate-500">pass rate</span></div>
      <div className="mt-2 flex gap-4 text-slate-300"><span><b className="text-emerald-300">{p.passed}</b> passed</span><span><b className="text-rose-300">{p.failed}</b> failed</span><span className="text-slate-500">{p.n} evaluated</span></div>
    </div>
  );
}

/** Pass rate per day (first evaluations only) as a line with area fill. */
export function PassRateTrend({ data, height = 200 }: { data: { day: string; passed: number; failed: number }[]; height?: number }) {
  const ui = useUi(); const axis = axisOf(ui);
  const rows = data.filter((r) => r.passed + r.failed > 0).map((r) => ({ day: r.day, rate: Math.round((r.passed / (r.passed + r.failed)) * 100), n: r.passed + r.failed, passed: r.passed, failed: r.failed }));
  if (!rows.length) return <Empty text="No evaluated tests yet." h={height} />;
  const d = pad(rows, { rate: 0, n: 0, passed: 0, failed: 0 });
  return (
    <div style={{ filter: "drop-shadow(0 0 9px rgba(45,255,180,.55))" }}>
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={d} margin={{ left: 0, right: 12, top: 12 }}>
        <defs><linearGradient id="pr" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#2dffb4" stopOpacity={0.62} /><stop offset="55%" stopColor="#22d3ee" stopOpacity={0.16} /><stop offset="100%" stopColor="#34d399" stopOpacity={0} /></linearGradient></defs>
        <CartesianGrid stroke={ui.grid} vertical={false} />
        <XAxis dataKey="day" {...axis} /><YAxis {...axis} domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} width={46} tickFormatter={(v) => `${v}%`} />
        <Tooltip content={<PassTip />} cursor={{ stroke: "rgba(52,211,153,.4)", strokeDasharray: "3 3" }} />
        <Area type="monotone" dataKey="rate" stroke="#34d399" strokeWidth={2.4} fill="url(#pr)" dot={{ r: 3.5, fill: ui.dot, stroke: "#34d399", strokeWidth: 2 }}
          activeDot={{ r: 6, fill: "#34d399", stroke: "rgba(52,211,153,.32)", strokeWidth: 9 }} />
      </AreaChart>
    </ResponsiveContainer></div>
  );
}

/** Verified findings per day over the last 7 days: a gradient area (rose to amber) - the trend of risk. */
export function RiskTrend({ data, color = "#fb7185", height = 120 }: { data: { day: string; verified: number }[]; color?: string; height?: number }) {
  const ui = useUi();
  if (!data.length) return <Empty text="No findings yet." h={height} />;
  const d = pad(data.slice(-7), { verified: 0 });
  return (
    <div style={{ filter: `drop-shadow(0 0 10px ${color}88)` }}>
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={d} margin={{ left: 4, right: 8, top: 10, bottom: 0 }}>
        <defs>
          <linearGradient id="rk" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity={0.78} /><stop offset="50%" stopColor="#c026d3" stopOpacity={0.2} /><stop offset="100%" stopColor="#fbbf24" stopOpacity={0} /></linearGradient>
          <linearGradient id="rks" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stopColor="#fbbf24" /><stop offset="100%" stopColor={color} /></linearGradient>
        </defs>
        <XAxis dataKey="day" hide /><YAxis hide domain={[0, "dataMax + 1"]} />
        <Tooltip {...tip} formatter={(v: any) => [v, "Verified findings"]} cursor={{ stroke: `${color}66`, strokeDasharray: "3 3" }} />
        <Area type="monotone" dataKey="verified" stroke="url(#rks)" strokeWidth={2.4} fill="url(#rk)" dot={{ r: 3.5, fill: ui.dot, stroke: color, strokeWidth: 2 }} activeDot={{ r: 6, fill: color, stroke: `${color}55`, strokeWidth: 9 }} />
      </AreaChart>
    </ResponsiveContainer></div>
  );
}

/** Tiny axis-less area chart for KPI cards and the health panel. */
export function Spark({ values, color = "#aeb1ff", height = 40, id }: { values: number[]; color?: string; height?: number; id: string }) {
  const v = values.length > 1 ? values : [0, ...(values.length ? values : [0])];
  const data = v.map((n, i) => ({ i, n }));
  return (
    <div>
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ left: 0, right: 0, top: 6, bottom: 0 }}>
        <defs><linearGradient id={`sp-${id}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity={0.10} /><stop offset="100%" stopColor={color} stopOpacity={0} /></linearGradient></defs>
        <YAxis hide domain={[0, "dataMax"]} />
        <Area type="monotone" dataKey="n" stroke={color} strokeOpacity={0.6} strokeWidth={1.5} fill={`url(#sp-${id})`} dot={false} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer></div>
  );
}

export function SeverityBars({ counts, labels, height = 200 }: { counts: Record<string, number>; labels: Record<string, string>; height?: number }) {
  const ui = useUi();
  const data = ["critical", "high", "medium", "low", "info"].map((k) => ({ k, name: labels[k] || k, n: counts[k] || 0 }));
  if (!data.some((d) => d.n)) return <Empty text="No verified findings." h={height} />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16 }}>
        <XAxis type="number" allowDecimals={false} hide />
        <YAxis type="category" dataKey="name" tick={{ fill: ui.label, fontSize: 12 }} tickLine={false} axisLine={false} width={64} />
        <Tooltip {...tip} cursor={{ fill: ui.band }} />
        <Bar dataKey="n" name="Findings" radius={[0, 6, 6, 0]} barSize={14} background={{ fill: ui.band, radius: 6 } as any}>{data.map((d) => <Cell key={d.k} fill={SEV_COLOR[d.k]} />)}</Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** OWASP compliance: the score as a large number plus one segment per LLM01-LLM10 category, colored by status. */
export function ComplianceMeter({ score, coverage, tested, total, categories }: { score: number | null; coverage: number; tested: number; total: number; categories?: { code: string; status: string }[] }) {
  const color = score == null ? "text-slate-500" : score >= 80 ? "text-emerald-300" : score >= 50 ? "text-amber-300" : "text-rose-300";
  return (
    <div>
      <div className="flex items-end gap-3">
        <div className={cn("text-[44px] font-semibold leading-none tracking-tight tabular", color)}>{score == null ? "-" : `${score}%`}</div>
        <div className="pb-1 text-xs text-slate-500">compliance score<br />coverage {tested}/{total} · {coverage}%</div>
      </div>
      <div className="mt-6 grid grid-cols-10 gap-1.5">
        {(categories?.length ? categories : Array.from({ length: total }, (_, i) => ({ code: `LLM${String(i + 1).padStart(2, "0")}`, status: "not_tested" }))).map((c) => {
          const st = OWASP_STATUS[c.status as OwaspStatus] ?? OWASP_STATUS.not_tested;
          return <div key={c.code} title={`${c.code} · ${st.label}`} className={cn("h-2 rounded-full transition-all hover:h-3", st.bar)} />;
        })}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-500">
        {(["clean", "review", "vulnerable", "not_tested"] as OwaspStatus[]).map((k) => <span key={k} className="flex items-center gap-1.5"><i className={cn("h-1.5 w-1.5 rounded-full", OWASP_STATUS[k].bar)} />{OWASP_STATUS[k].label}</span>)}
      </div>
    </div>
  );
}

/** One colour per compared model (stable by position; chosen to stay distinguishable on the dark glass cards). */
export const MODEL_COLORS = ["#a5a6fb", "#34d399", "#fbbf24", "#f472b6"];

type BenchTarget = { model: string; endpoint_url: string; categories: Record<string, { tested: number; fail_rate: number | null }> };
const short = (id: string) => id.split("_")[0];

/** Side-by-side failure rate per OWASP category: one bar per model inside each category group. */
export function ModelCompareBars({ categories, targets, height = 260 }: { categories: string[]; targets: BenchTarget[]; height?: number }) {
  const ui = useUi(); const axis = axisOf(ui);
  if (!categories.length) return <Empty text="No evaluated tests yet." h={height} />;
  const data = categories.map((c) => Object.fromEntries([["cat", short(c)], ...targets.map((t, i) => [`m${i}`, t.categories[c]?.fail_rate == null ? null : Math.round((t.categories[c].fail_rate as number) * 100)])]));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ left: 4, right: 8, top: 8 }} barGap={3} barCategoryGap="22%">
        <CartesianGrid stroke={ui.grid} vertical={false} />
        <XAxis dataKey="cat" {...axis} /><YAxis {...axis} width={46} domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tickFormatter={(v) => `${v}%`} />
        <Tooltip {...tip} cursor={{ fill: ui.band }} formatter={(v: any, n: any) => [v == null ? "not tested" : `${v}%`, targets[+String(n).slice(1)]?.model ?? n]} />
        {targets.map((t, i) => <Bar key={t.endpoint_url} dataKey={`m${i}`} name={`m${i}`} fill={MODEL_COLORS[i % MODEL_COLORS.length]} radius={[5, 5, 0, 0]} maxBarSize={22} minPointSize={2} />)}
      </BarChart>
    </ResponsiveContainer>
  );
}

/** The same data as a radar: the larger the area, the more tests the model failed. */
export function ModelRadar({ categories, targets, height = 300 }: { categories: string[]; targets: BenchTarget[]; height?: number }) {
  const ui = useUi();
  if (categories.length < 3) return <Empty text="A radar needs at least three tested categories." h={height} />;
  const data = categories.map((c) => Object.fromEntries([["cat", short(c)], ...targets.map((t, i) => [`m${i}`, Math.round((t.categories[c]?.fail_rate ?? 0) * 100)])]));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <RadarChart data={data} outerRadius="72%">
        <PolarGrid stroke={ui.polar} /><PolarAngleAxis dataKey="cat" tick={{ fill: ui.label, fontSize: 11 }} /><PolarRadiusAxis domain={[0, 100]} tick={false} axisLine={false} />
        {targets.map((t, i) => <Radar key={t.endpoint_url} dataKey={`m${i}`} name={t.model} stroke={MODEL_COLORS[i % MODEL_COLORS.length]} fill={MODEL_COLORS[i % MODEL_COLORS.length]} fillOpacity={0.14} strokeWidth={2} />)}
        <Tooltip {...tip} formatter={(v: any, n: any) => [`${v}%`, n]} />
      </RadarChart>
    </ResponsiveContainer>
  );
}
