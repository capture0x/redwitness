"use client";
import { ArrowRightLeft, Scale } from "lucide-react";
import { api, usePoll } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Hint, Label, NativeSelect } from "@/components/ui/input";

const TONE: Record<string, any> = { independent: "green", same_family: "amber", same_model: "red", unknown: "neutral" };
const TEXT: Record<string, string> = { independent: "independent", same_family: "same family", same_model: "same model", unknown: "unknown" };

/** Settings card: bias policy + model comparison and judge assignment (presets are applied to the form; nothing changes until Save). */
export default function BiasControl({ f, set }: { f: any; set: (k: string, v: any) => void }) {
  const { data: targets } = usePoll<any[]>(() => api("/targets"), 0);
  const body = JSON.stringify({ targets: (targets || []).map((t: any) => ({ provider: t.provider, model: t.model, url: t.request_url, name: t.name })) });
  const { data } = usePoll<any>(() => api("/bias/assess", { method: "POST", body }), 0, [body, f.judge_provider, f.judge_model]);
  const apply = (s: any) => { for (const [k, v] of Object.entries(s.settings)) set(k, v); };
  return (
    <Card data-testid="bias-control"><CardHeader><div><CardTitle>Bias control</CardTitle><CardDescription>A judge from the same model family as the target tends to favour its own style (self-preference bias). Prefer a judge from a different provider.</CardDescription></div><Scale className="h-4 w-4 text-slate-500" /></CardHeader>
      <CardContent className="space-y-4">
        <div><Label>Policy when the judge is not independent of the target</Label>
          <NativeSelect data-testid="bias-policy" value={f.bias_policy || "warn"} onChange={(e) => set("bias_policy", e.target.value)}>
            <option value="warn">warn - show a warning, still run</option><option value="block">block - refuse to start the run</option><option value="off">off - no check</option></NativeSelect>
          <Hint>Unknown model families are only warned about, never blocked.</Hint></div>
        <div className="space-y-2.5" data-testid="bias-table">
          <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-slate-500"><ArrowRightLeft className="h-3.5 w-3.5" />Model comparison and assignment</div>
          {data && <div className="text-xs text-slate-400">Current judge: <b className="text-slate-200">{data.judge.model}</b> · {data.families?.[data.judge.family] || data.judge.family}</div>}
          {!targets?.length && <p className="text-xs text-slate-500">No saved targets yet. Add one on the Targets page to compare it with the judge.</p>}
          {data?.targets?.map((t: any, i: number) => (
            <div key={i} className="rounded-xl border border-white/[0.08] bg-black/20 p-3">
              <div className="flex flex-wrap items-center gap-2 text-sm"><span className="font-medium text-slate-100">{t.target.name || t.target.model}</span><span className="text-xs text-slate-500">{t.target.model} · {t.family_label}</span>
                <Badge tone={TONE[t.judge.level]} title={t.judge.message}>judge: {TEXT[t.judge.level]}</Badge>
                {t.verifier && <Badge tone={TONE[t.verifier.level]} title={t.verifier.message}>verifier: {TEXT[t.verifier.level]}</Badge>}</div>
              {t.judge.level !== "independent" && <div className="mt-2 flex flex-wrap items-center gap-2"><span className="text-xs text-slate-500">Independent judge for this target:</span>
                {t.suggestions.map((s: any) => <Button key={s.family} type="button" variant="secondary" size="sm" title={s.key_present ? `${s.settings.judge_api_key_env} is set on the server` : `${s.settings.judge_api_key_env} is not set on the server yet`} onClick={() => apply(s)}>{s.label}{!s.key_present && " (no key)"}</Button>)}</div>}
            </div>))}
          <Hint>Choosing a suggestion fills the judge fields above (model names are defaults; edit them to what your account offers). Press <b>Save</b> to apply. The API key itself is never entered here.</Hint>
        </div>
      </CardContent></Card>
  );
}
