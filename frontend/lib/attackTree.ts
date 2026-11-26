/** Turns a finding's run data (attempts + Attacker agent steps) into a left-to-right decision graph. Pure: no React, no fetching. */
export type Tone = "info" | "ok" | "bad" | "warn" | "mute" | "agent";
export type TreeNode = { id: string; kind: "case" | "attempt" | "agent" | "replay" | "outcome"; title: string; sub?: string; tone: Tone; detail?: { label: string; text: string }[] };
export type TreeEdge = { id: string; source: string; target: string; label?: string; hot?: boolean };
export type Tree = { nodes: TreeNode[]; edges: TreeEdge[] };

type Attempt = { seq: number; case_id: string; conversation_id: string; turn: number; prompt: string; response: string | null; outcome: string; evaluation_json?: string | null; evaluation?: any; blocked_reason?: string | null; is_replay: number | boolean };
type Step = { seq: number; case_id: string; round: number; state: string; detail: Record<string, any> };

const clip = (s: string | null | undefined, n = 600) => (s ? (s.length > n ? s.slice(0, n) + "…" : s) : "");
const evalOf = (a: Attempt) => a.evaluation ?? (a.evaluation_json ? JSON.parse(a.evaluation_json) : null);

export const STATUS_LABEL: Record<string, string> = { verified: "Verified finding", unstable: "Unstable (not reproducible)", candidate: "Candidate (replay incomplete)", needs_review: "Needs human review" };

export function buildTree(finding: { case_id: string; status: string; title: string; category: string; owasp_category?: string | null; evidence?: any }, attempts: Attempt[], steps: Step[]): Tree {
  const cid = finding.case_id;
  const mine = attempts.filter((a) => a.case_id === cid && a.conversation_id !== "cleanup");
  const convs = new Map<string, Attempt[]>();
  for (const a of mine) { const k = `${a.is_replay ? "r" : "f"}:${a.conversation_id}`; (convs.get(k) ?? convs.set(k, []).get(k)!).push(a); }
  const first = [...convs.entries()].filter(([k]) => k.startsWith("f:")).sort((x, y) => x[1][0].seq - y[1][0].seq);
  const replays = [...convs.entries()].filter(([k]) => k.startsWith("r:")).sort((x, y) => x[1][0].seq - y[1][0].seq);
  const mySteps = steps.filter((s) => s.case_id === cid);
  const byConv = new Map<string, Step>();                                  // adaptive conversation -> its ATTACKING step
  for (const s of mySteps) if (s.state === "attacking" && s.detail.conversation_id) byConv.set(s.detail.conversation_id, s);
  const roundInfo = (r: number) => ({ family: mySteps.find((s) => s.round === r && s.state === "generating")?.detail.family as string | undefined,
    rationale: mySteps.find((s) => s.round === r && s.state === "validating")?.detail.rationale as string | undefined,
    sha: mySteps.find((s) => s.round === r && s.state === "validating")?.detail.sha256 as string | undefined });

  const nodes: TreeNode[] = [{ id: "case", kind: "case", title: cid, sub: [finding.category.replace(/_/g, " "), finding.owasp_category?.split("_")[0]].filter(Boolean).join(" · "), tone: "info",
    detail: [{ label: "Test case", text: finding.title }] }];
  const edges: TreeEdge[] = [];
  let prev = "case", prevRefused = false, statics = 0;
  const link = (to: string, label?: string, hot = false) => { edges.push({ id: `${prev}->${to}`, source: prev, target: to, label, hot }); prev = to; };

  first.forEach(([key, rows], i) => {
    const judged = rows.find((r) => r.outcome.startsWith("judged:"));
    const sent = [...rows].reverse().find((r) => r.outcome === "sent") ?? rows[0];
    const ev = judged ? evalOf(judged) : null;
    const verdict: string | null = ev?.verdict ?? null;
    const failed = !judged ? rows.find((r) => r.outcome === "blocked" || r.outcome === "error") : null;
    const step = byConv.get(key.slice(2));
    const adaptive = !!step;
    const tone: Tone = verdict === "violation" ? "bad" : verdict === "no_violation" ? (ev?.refusal_detected ? "warn" : "ok") : failed ? "warn" : "mute";
    if (adaptive) {                                                         // the agent's decision nodes sit between two attempts
      const ri = roundInfo(step!.round);
      const an = `a${i}`;
      nodes.push({ id: an, kind: "agent", tone: "agent", title: `Attacker · ${ri.family ?? "rewrite"}`, sub: `round ${step!.round}${ri.sha ? ` · ${ri.sha.slice(0, 8)}` : ""}`,
        detail: [{ label: "What the Attacker changed", text: ri.rationale || "-" }, { label: "Allowed family", text: ri.family || "-" }] });
      link(an, prevRefused ? "refused" : undefined);
    } else statics += 1;
    const id = `t${i}`;
    nodes.push({ id, kind: "attempt", tone, title: adaptive ? `Rewrite #${step!.round}` : statics === 1 ? "Library message" : `Library variant ${statics}`,
      sub: failed ? `${failed.outcome}${failed.blocked_reason ? " · " + failed.blocked_reason : ""}` : verdict ? `${verdict.replace("_", " ")}${ev?.confidence != null ? ` · ${ev.confidence}` : ""}${ev?.refusal_detected ? " · refused" : ""}` : "sent",
      detail: [{ label: "Sent to target", text: clip(sent?.prompt) }, { label: "Target replied", text: clip(sent?.response) }, ...(ev?.rationale ? [{ label: "Judge rationale", text: clip(ev.rationale, 400) }] : [])] });
    link(id, !adaptive && i > 0 ? "refused" : undefined, verdict === "violation");
    prevRefused = !!ev?.refusal_detected;
  });

  if (replays.length) {
    const viol = replays.filter(([, rows]) => evalOf(rows.find((r) => r.outcome.startsWith("judged:")) ?? ({} as Attempt))?.verdict === "violation").length;
    nodes.push({ id: "rp", kind: "replay", tone: viol ? "bad" : "ok", title: `Replayed ${replays.length}×`, sub: `${viol} violation${viol === 1 ? "" : "s"}`,
      detail: [{ label: "Replay", text: `Each replay used a brand-new conversation. Required ${finding.evidence?.replay?.required ?? "?"} of ${finding.evidence?.replay?.requested ?? "?"}.` }] });
    link("rp", "replay", true);
  }
  const term = [...mySteps].reverse().find((s) => ["exhausted", "aborted", "halted", "clean"].includes(s.state));
  nodes.push({ id: "end", kind: "outcome", tone: finding.status === "verified" ? "bad" : finding.status === "unstable" ? "warn" : "mute", title: STATUS_LABEL[finding.status] ?? finding.status,
    sub: term && finding.status !== "verified" ? `agent: ${term.state}` : undefined, detail: [{ label: "Finding", text: finding.title }] });
  link("end", undefined, finding.status === "verified");
  return { nodes, edges };
}
