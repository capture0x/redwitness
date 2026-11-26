import { Fade } from "./motion";
export default function PageHeader({ title, sub, right }: { title: string; sub?: string; right?: React.ReactNode }) {
  return (
    <Fade className="mb-9 flex flex-wrap items-end justify-between gap-5">
      <div><h1 className="text-[26px] font-semibold leading-tight tracking-tight text-white">{title}</h1>{sub && <p className="mt-2 max-w-2xl text-[13.5px] leading-relaxed text-slate-400">{sub}</p>}</div>
      {right && <div className="flex items-center gap-2.5">{right}</div>}
    </Fade>
  );
}
export const Notice = ({ tone = "amber", children }: { tone?: "amber" | "red" | "green" | "blue"; children: React.ReactNode }) => {
  const c = { amber: "border-amber-400/25 bg-amber-500/[0.07] text-amber-100", red: "border-rose-400/25 bg-rose-500/[0.07] text-rose-100", green: "border-emerald-400/25 bg-emerald-500/[0.07] text-emerald-100", blue: "border-sky-400/25 bg-sky-500/[0.07] text-sky-100" }[tone];
  return <div className={`mb-5 rounded-xl border px-4 py-3 text-[13px] leading-relaxed ${c}`}>{children}</div>;
};
