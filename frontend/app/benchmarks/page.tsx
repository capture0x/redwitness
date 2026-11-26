"use client";
import Link from "next/link";
import { GitCompareArrows, Plus } from "lucide-react";
import PageHeader from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { api, fmtDate, usePoll } from "@/lib/api";
import { useMe } from "@/lib/me";

export default function Benchmarks() {
  const { can } = useMe();
  const { data } = usePoll(() => api("/benchmarks"), 5000);
  return (
    <>
      <PageHeader title="Model benchmarks" sub="Send one test set to two to four targets and compare how often each model fails, category by category."
        right={can("operator") ? <Link href="/new?compare=1"><Button><Plus className="h-4 w-4" />New benchmark</Button></Link> : undefined} />
      {!data ? <Skeleton className="h-40" /> : data.length === 0 ? <Card className="py-14 text-center text-sm text-slate-500">No benchmarks yet. Start one from “New Test” → “Compare multiple targets”.</Card> : (
        <div className="grid gap-3">{data.map((b: any) => (
          <Link key={b.id} href={`/benchmarks/${b.id}`}><Card className="surface-hover flex items-center gap-4 p-5"><GitCompareArrows className="h-5 w-5 text-indigo-300" />
            <div className="flex-1"><div className="font-medium text-white">{b.label}</div><div className="text-xs text-slate-500">{b.targets} targets · {fmtDate(b.created_at)} · {b.created_by}</div></div><span className="text-xs text-indigo-300">Open →</span></Card></Link>))}</div>)}
    </>
  );
}
