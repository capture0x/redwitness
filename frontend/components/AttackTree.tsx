"use client";
import "@xyflow/react/dist/style.css";
import { useTheme } from "@/lib/theme";
import { Background, BackgroundVariant, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Bot, FlaskConical, Flag, MessageSquare, Repeat } from "lucide-react";
import { api } from "@/lib/api";
import { buildTree, type Tone, type TreeNode } from "@/lib/attackTree";
import { Skeleton } from "@/components/ui/misc";
import { cn } from "@/lib/utils";

const RING: Record<Tone, string> = {
  info: "border-sky-400/30 bg-sky-500/[0.07]", ok: "border-emerald-400/30 bg-emerald-500/[0.07]", bad: "border-rose-400/40 bg-rose-500/[0.09]",
  warn: "border-amber-400/30 bg-amber-500/[0.07]", mute: "border-white/10 bg-white/[0.03]", agent: "border-indigo-400/35 bg-indigo-500/[0.09]",
};
const DOT: Record<Tone, string> = { info: "bg-sky-400", ok: "bg-emerald-400", bad: "bg-rose-400", warn: "bg-amber-400", mute: "bg-slate-500", agent: "bg-indigo-300" };
const ICON = { case: FlaskConical, attempt: MessageSquare, agent: Bot, replay: Repeat, outcome: Flag } as const;

function StepNode({ data, selected }: NodeProps<Node<{ n: TreeNode }>>) {
  const n = data.n, Icon = ICON[n.kind];
  return (
    <div className={cn("w-[170px] rounded-xl border px-3 py-2.5 text-left shadow-lg backdrop-blur transition", RING[n.tone], selected && "ring-2 ring-indigo-300/70")}>
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-0 !bg-slate-500" />
      <div className="flex items-center gap-2"><Icon className="h-3.5 w-3.5 shrink-0 text-slate-300" /><span className="truncate text-[12px] font-medium text-slate-100">{n.title}</span></div>
      {n.sub && <div className="mt-1 flex items-center gap-1.5 text-[11px] text-slate-400"><i className={cn("h-1.5 w-1.5 rounded-full", DOT[n.tone])} /><span className="truncate">{n.sub}</span></div>}
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-0 !bg-slate-500" />
    </div>
  );
}
const nodeTypes = { step: StepNode };

/** Visual attack tree for one finding: what the agent tried, why it moved on, and how the verdict was reached. */
export default function AttackTree({ f }: { f: any }) {
  const run = useQuery({ queryKey: ["tree-run", f.run_id], queryFn: () => api(`/runs/${f.run_id}`), staleTime: 15_000 });
  const steps = useQuery({ queryKey: ["tree-steps", f.run_id, f.case_id], queryFn: () => api(`/runs/${f.run_id}/agent-steps?case_id=${encodeURIComponent(f.case_id)}`), staleTime: 15_000 });
  const [sel, setSel] = useState<string>("end");
  const light = useTheme() === "light";
  const tree = useMemo(() => (run.data && steps.data ? buildTree(f, run.data.attempts ?? [], steps.data) : null), [f, run.data, steps.data]);
  const { nodes, edges } = useMemo(() => {
    if (!tree) return { nodes: [] as Node[], edges: [] as Edge[] };
    return {
      nodes: tree.nodes.map((n, i): Node => ({ id: n.id, type: "step", position: { x: i * 215, y: 0 }, data: { n }, selected: n.id === sel, draggable: false })),
      edges: tree.edges.map((e): Edge => ({ id: e.id, source: e.source, target: e.target, label: e.label, animated: !!e.hot, markerEnd: { type: MarkerType.ArrowClosed, color: e.hot ? "#fb7185" : light ? "#a1a1aa" : "#64748b" },
        style: { stroke: e.hot ? "#fb7185" : light ? "#a1a1aa" : "#475569", strokeWidth: e.hot ? 2 : 1.4 }, labelStyle: { fill: light ? "#52525b" : "#94a3b8", fontSize: 10 }, labelBgStyle: { fill: light ? "#ffffff" : "#0b0c13" } })),
    };
  }, [tree, sel, light]);
  if (run.error || steps.error) return <p className="text-sm text-rose-300">Could not load the attack tree.</p>;
  if (!tree) return <Skeleton className="h-[260px] w-full" />;
  const chosen = tree.nodes.find((n) => n.id === sel) ?? tree.nodes[tree.nodes.length - 1];
  const adaptive = tree.nodes.some((n) => n.kind === "agent");
  return (
    <div className="space-y-3">
      <div className="h-[230px] overflow-hidden rounded-xl border border-white/[0.07] bg-black/25" data-testid="attack-tree">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.08, maxZoom: 1 }} minZoom={0.3} colorMode={light ? "light" : "dark"} nodesDraggable={false} nodesConnectable={false}
          proOptions={{ hideAttribution: true }} onNodeClick={(_, n) => setSel(n.id)}>
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} color={light ? "rgba(16,18,27,.12)" : "rgba(255,255,255,.07)"} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <p className="text-[11px] text-slate-500">{adaptive ? "Violet nodes are Attacker-agent decisions (each rewrite stays inside the operator's allowed families). " : "No Attacker rewrites were used for this case. "}Red edges are the path that reached the finding. Click a node for details.</p>
      <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-4 text-xs">
        <div className="mb-2 text-[13px] font-medium text-slate-100">{chosen.title}{chosen.sub && <span className="ml-2 font-normal text-slate-500">{chosen.sub}</span>}</div>
        {chosen.detail?.map((d) => <div key={d.label} className="mb-2"><div className="mb-0.5 text-[10px] uppercase tracking-wider text-slate-500">{d.label}</div><pre className="max-h-40 overflow-auto whitespace-pre-wrap text-slate-300">{d.text || "-"}</pre></div>)}
      </div>
    </div>
  );
}
