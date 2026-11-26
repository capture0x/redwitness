"use client";
import { useState } from "react";
import { ScrollText } from "lucide-react";
import { api, fmtDate, usePoll } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { NativeSelect } from "@/components/ui/input";

const TONE: Record<string, any> = { scope_state: "red", endpoint: "red", control: "red", limits: "amber", attack_class: "violet" };

export default function Audit() {
  const [cat, setCat] = useState("");
  const [code, setCode] = useState("");
  const { data: reasons } = usePoll(() => api("/reasons"), 0);
  const { data: rows } = usePoll(() => api(`/audit?category=${cat}&code=${code}`), 4000, [cat, code]);
  const cats = Array.from(new Map((reasons || []).filter((r: any) => r.category !== "allow").map((r: any) => [r.category, r.category_label])).entries());
  const codes = (reasons || []).filter((r: any) => r.category !== "allow" && (!cat || r.category === cat));
  return (
    <>
      <PageHeader title="Audit - refusal and limit records" sub="Every refusal is recorded with its own code; no refusal passes silently. Records are hash-chained and cannot be changed." />
      <div className="mb-5 flex flex-wrap gap-3">
        <div className="w-60"><NativeSelect value={cat} onChange={(e) => { setCat(e.target.value); setCode(""); }}><option value="">All categories</option>{cats.map(([k, v]: any) => <option key={k} value={k}>{v}</option>)}</NativeSelect></div>
        <div className="w-72"><NativeSelect value={code} onChange={(e) => setCode(e.target.value)}><option value="">All codes</option>{codes.map((r: any) => <option key={r.code} value={r.code}>{r.code}</option>)}</NativeSelect></div>
      </div>
      <Card className="overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-white/[0.07] text-left text-[11px] uppercase tracking-wider text-slate-500"><th className="px-5 py-3">Time</th><th>Category</th><th>Code</th><th className="pr-5">Why it was refused</th></tr></thead>
          <tbody>
            {rows?.map((r: any) => (
              <tr key={r.seq} className="border-b border-white/[0.05] align-top transition hover:bg-white/[0.03]">
                <td className="whitespace-nowrap px-5 py-3 text-xs text-slate-500">{fmtDate(r.at)}</td>
                <td className="pr-3 pt-3"><Badge tone={TONE[r.reason_category] || "neutral"}>{reasons?.find((x: any) => x.code === r.reason_code)?.category_label || r.reason_category}</Badge></td>
                <td className="pr-3 pt-3.5 font-mono text-xs text-slate-300">{r.reason_code}</td>
                <td className="py-3 pr-5 text-slate-300">{r.explanation}<div className="mt-1 truncate font-mono text-[11px] text-slate-600">{r.action} {Object.keys(r.detail || {}).length ? JSON.stringify(r.detail).slice(0, 150) : ""}</div></td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows && rows.length === 0 && <div className="flex flex-col items-center py-14 text-sm text-slate-500"><ScrollText className="mb-3 h-9 w-9 text-slate-700" />No records match these filters.</div>}
      </Card>
    </>
  );
}
