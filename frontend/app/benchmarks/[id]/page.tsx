"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { CompareChart, CompareTable, Leaderboard } from "@/components/BenchmarkView";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/misc";
import { api, fmtDate, usePoll } from "@/lib/api";

export default function BenchmarkPage() {
  const { id } = useParams<{ id: string }>();
  const { data: b, error } = usePoll(() => api(`/benchmarks/${id}`), 2500, [id]);
  if (error) return <Notice tone="red">{error}</Notice>;
  if (!b) return <div className="space-y-4"><Skeleton className="h-12 w-72" /><Skeleton className="h-40" /><Skeleton className="h-72" /></div>;
  return (
    <>
      <Link href="/benchmarks" className="mb-3 inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"><ArrowLeft className="h-3 w-3" />All benchmarks</Link>
      <PageHeader title={b.label} sub={`${b.targets.length} targets · same test set, same limits and replay settings · started ${fmtDate(b.created_at)} by ${b.created_by}`}
        right={<Badge tone={b.status === "completed" ? "green" : b.status === "running" ? "blue" : "amber"}>{b.status}</Badge>} />
      <Notice tone="blue">A benchmark compares how often each model failed the <b>same</b> tests. It is a small, non-statistical sample: use it to spot clear differences between models, not to claim a precise ranking or a compliance result.</Notice>
      <div className="mb-6"><Leaderboard b={b} /></div>
      <div className="mb-6"><CompareChart b={b} /></div>
      <CompareTable b={b} />
    </>
  );
}
