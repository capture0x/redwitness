"use client";
import { useState } from "react";
import { BookOpenCheck, Download, FileText, FileUp, Layers, Package, Save, ShieldCheck, Sparkles, Wrench } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api, fmtDate, usePoll } from "@/lib/api";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NativeSelect, Textarea } from "@/components/ui/input";
import Dropzone from "@/components/Dropzone";
import { Item, Stagger } from "@/components/motion";
import { cn } from "@/lib/utils";
import { useMe } from "@/lib/me";

export default function Library() {
  const { data: libs, reload } = usePoll(() => api("/libraries"), 0);
  const { data: meta } = usePoll(() => api("/meta"), 0);
  const { can } = useMe();
  const { data: tpl } = usePoll(() => api("/templates"), 0);
  const [tab, setTab] = useState("mine");
  const [busy, setBusy] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [sel, setSel] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [bk, setBk] = useState("harmbench");
  const [bnote, setBnote] = useState<string | null>(null);
  const [pfmt, setPfmt] = useState("lines");
  const [pfam, setPfam] = useState("");
  const [psrc, setPsrc] = useState("");
  const [pmt, setPmt] = useState("sequence");
  const [pnote, setPnote] = useState<string | null>(null);
  const open = async (id: string) => { const d = await api(`/libraries/${id}`); setSel(d); setText(d.content); setErr(null); };
  const save = async () => {
    setErr(null); setOk(null);
    try { const r = await api("/libraries", { method: "POST", body: JSON.stringify({ content: text }) }); setOk(`Saved: ${r.name} v${r.version} · ${r.cases} cases · sha256 ${r.sha256.slice(0, 12)}…`); reload(); open(r.id); }
    catch (e: any) { setErr(e.message); }
  };
  const importTpl = async (body: any, label: string) => {
    setBusy(label); setErr(null); setOk(null);
    try { const r = await api("/templates/import", { method: "POST", body: JSON.stringify(body) }); setOk(`${r.imported.length} template(s) imported (${r.imported.reduce((a: number, x: any) => a + x.cases, 0)} cases). The same content is never added twice.`); reload(); }
    catch (e: any) { setErr(e.message); } finally { setBusy(null); }
  };
  const catLabel = (id: string) => meta?.attack_classes?.find((a: any) => a.id === id)?.label || id;
  return (
    <>
      <PageHeader title="Test Library" sub="External JSON/YAML test cases. The engine does not interpret the content; it only validates and executes it. Editing = a new version (the content digest changes)." />
      {err && <Notice tone="red">{err}</Notice>}{ok && <Notice tone="green">{ok}</Notice>}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="mb-4"><TabsTrigger value="mine"><Layers className="mr-1.5 inline h-3.5 w-3.5" />My libraries</TabsTrigger>
          <TabsTrigger value="starter"><Package className="mr-1.5 inline h-3.5 w-3.5" />Ready-made templates (OWASP)</TabsTrigger></TabsList>
      <TabsContent value="mine">
      {can("operator") && <Card className="mb-5"><CardContent className="p-5">
        <Dropzone accept={[".json", ".yaml", ".yml"]} testId="lib-dropzone" busy={busy === "upload"} title="Upload a test library (JSON or YAML)" hint="Drag a file here or click to browse · .json .yaml .yml · it is validated before it is saved"
          onFile={async (file) => { setBusy("upload"); setErr(null); setOk(null); try { const r = await api("/libraries", { method: "POST", body: JSON.stringify({ content: await file.text() }) }); setOk(`Uploaded ${file.name}: ${r.name} v${r.version} · ${r.cases} cases · sha256 ${r.sha256.slice(0, 12)}…`); reload(); open(r.id); } catch (e: any) { setErr(`${file.name}: ${e.message}`); } finally { setBusy(null); } }} />
        {ok && <div className="mt-3 text-sm text-emerald-300" data-testid="lib-ok">{ok}</div>}{err && <div className="mt-3 text-sm text-red-400" role="alert" data-testid="lib-err">{err}</div>}</CardContent></Card>}
      {can("operator") && <Card className="mb-5"><CardContent className="p-5" data-testid="bench-import">
        <div className="mb-3 flex flex-wrap items-center gap-3"><div className="text-[15px] font-semibold text-white">Import a benchmark dataset</div>
          <select value={bk} onChange={(e) => setBk(e.target.value)} data-testid="bench-kind" className="rounded-lg border border-white/15 bg-white/[0.05] px-2.5 py-1.5 text-sm text-slate-200">
            <option value="harmbench">HarmBench (CSV)</option><option value="jailbreakbench">JailbreakBench (CSV/JSON)</option><option value="strongreject">StrongREJECT (CSV)</option></select></div>
        <p className="mb-3 text-xs text-slate-400">Upload the file published by the benchmark project. Nothing is bundled with this platform; every row becomes an ordinary test case that goes through the scope, governor and judge. Results are reported as Attack Success Rate (ASR) in Compliance Suite.</p>
        <Dropzone accept={[".csv", ".json"]} testId="bench-dropzone" busy={busy === "bench"} title="Drop the benchmark file" hint="Drag a file here or click to browse · .csv .json"
          onFile={async (file) => { setBusy("bench"); setErr(null); setBnote(null); try { const r = await api("/libraries/import-benchmark", { method: "POST", body: JSON.stringify({ kind: bk, content: await file.text() }) });
            const rp = r.report; setBnote(`Imported ${r.cases} ${bk} cases (skipped: ${rp.skipped_unsupported} unsupported, ${rp.skipped_empty} empty, ${rp.skipped_too_long} too long)${rp.truncated_by_limit ? " · limited to 2000 cases" : ""}.`); reload(); open(r.id); } catch (e: any) { setErr(`${file.name}: ${e.message}`); } finally { setBusy(null); } }} />
        {bnote && <div className="mt-3 text-sm text-emerald-300" data-testid="bench-note">{bnote}</div>}</CardContent></Card>}
      {can("operator") && <Card className="mb-5"><CardContent className="p-5" data-testid="payload-import">
        <div className="mb-3 text-[15px] font-semibold text-white">Import an external payload library</div>
        <p className="mb-3 text-xs text-slate-400">Bring your own file (for example a plain-text payload list, a JSON/JSONL/CSV file, or AltayDuel transcripts). Payloads are stored word for word as library messages: the platform only adds the attack-family tag (which fills the ATLAS and Agentic mapping), the scope class and the source note. Nothing is bundled, and you are responsible for the dataset's licence.</p>
        <div className="mb-3 grid gap-3 md:grid-cols-4">
          <label className="text-xs text-slate-400">File layout<NativeSelect value={pfmt} onChange={(e) => setPfmt(e.target.value)} data-testid="payload-format"><option value="lines">One payload per line (.txt)</option><option value="records">Records (JSON, JSONL, CSV, YAML)</option><option value="altayduel">AltayDuel transcripts (JSONL)</option></NativeSelect></label>
          <label className="text-xs text-slate-400">Attack family<NativeSelect value={pfam} onChange={(e) => setPfam(e.target.value)} data-testid="payload-family"><option value="">Detect from labels / file name</option>{["instruction_override", "role_play", "encoding_evasion", "payload_splitting", "memory_poisoning", "tool_abuse", "exfiltration"].map((f) => <option key={f} value={f}>{f.replace(/_/g, " ")}</option>)}</NativeSelect></label>
          <label className="text-xs text-slate-400">Multi-turn files<NativeSelect value={pmt} onChange={(e) => setPmt(e.target.value)} data-testid="payload-multiturn"><option value="sequence">Fixed turn sequence</option><option value="branching">Branching (stop on refusal; needs the scope permission)</option></NativeSelect></label>
          <label className="text-xs text-slate-400">Source / licence note<input value={psrc} onChange={(e) => setPsrc(e.target.value)} maxLength={200} placeholder="dataset name, licence" data-testid="payload-source" className="mt-1 w-full rounded-lg border border-white/15 bg-white/[0.05] px-2.5 py-1.5 text-sm text-slate-200" /></label></div>
        <Dropzone accept={[".txt", ".json", ".jsonl", ".csv", ".yaml", ".yml"]} testId="payload-dropzone" busy={busy === "payload"} title="Drop the payload file" hint="Drag a file here or click to browse · .txt .json .jsonl .csv .yaml · the folder name in the file name (e.g. memory-poisoning_notes.txt) is used to detect the family"
          onFile={async (file) => { setBusy("payload"); setErr(null); setPnote(null); try { const r = await api("/libraries/import-payloads", { method: "POST", body: JSON.stringify({ content: await file.text(), format: pfmt, name: file.name, source: psrc, family: pfam || null, path_hint: file.name, multi_turn: pmt }) });
            const rp = r.report; setPnote(`Imported ${r.cases} cases · ${Object.entries(rp.by_family).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join(", ")} (skipped: ${rp.skipped_duplicate} duplicate, ${rp.skipped_empty} empty, ${rp.skipped_too_long} too long, ${rp.skipped_placeholder} reserved placeholder)${rp.truncated_by_limit ? " · limited to 2000 cases" : ""}.`); reload(); open(r.id); } catch (e: any) { setErr(`${file.name}: ${e.message}`); } finally { setBusy(null); } }} />
        {pnote && <div className="mt-3 text-sm text-emerald-300" data-testid="payload-note">{pnote}</div>}</CardContent></Card>}
      <div className="grid gap-5 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-2">
          <Card><CardHeader><CardTitle>Loaded libraries</CardTitle><Layers className="h-4 w-4 text-slate-500" /></CardHeader>
            <CardContent className="space-y-2 pt-3">
              {libs && !libs.length && (
                <div data-testid="library-empty" className="py-8 text-center"><p className="text-sm text-slate-300">No test library yet.</p>
                  <p className="mx-auto mt-1 max-w-xs text-xs leading-relaxed text-slate-500">A library holds the test messages a scan sends. The quickest start is the ready-made OWASP templates.</p>
                  <Button className="mt-4" size="sm" onClick={() => setTab("starter")}><Package className="h-3.5 w-3.5" />Browse ready-made templates</Button></div>)}
              <Stagger>{libs?.map((l: any) => (
                <Item key={l.id}><button onClick={() => open(l.id)} className={cn("mb-2 w-full rounded-xl border px-4 py-3 text-left transition", sel?.id === l.id ? "border-violet-400/50 bg-violet-500/10 shadow-glow" : "border-white/10 hover:border-white/25 hover:bg-white/[0.04]")}>
                  <div className="flex items-center gap-2 text-sm font-medium text-white"><BookOpenCheck className="h-4 w-4 text-violet-300" />{l.name}<span className="text-xs font-normal text-slate-500">v{l.version}</span></div>
                  <div className="mt-1 text-xs text-slate-500">{l.cases} cases · {fmtDate(l.created_at)} · <span className="font-mono">{l.sha256.slice(0, 12)}…</span></div></button></Item>))}</Stagger>
            </CardContent></Card>
          {sel && <Card><CardHeader><div><CardTitle>Cases</CardTitle><CardDescription>{sel.case_list.length} items</CardDescription></div></CardHeader>
            <CardContent className="max-h-96 space-y-2 overflow-y-auto pt-3">{sel.case_list.map((c: any) => (
              <div key={c.id} className="rounded-xl border border-white/10 bg-black/20 px-3 py-2 text-xs">
                <div className="flex items-center justify-between gap-2"><span className="font-mono text-slate-200">{c.id}</span><Badge tone="violet">{catLabel(c.category)}</Badge></div>
                <div className="mt-1 text-slate-500">{c.title || c.expected_behavior} · {c.turns} tur · {c.variants} varyant · red: {c.on_refusal}</div></div>))}</CardContent></Card>}
        </div>
        <Card className="lg:col-span-3"><CardHeader><div><CardTitle>Edit / import</CardTitle><CardDescription>JSON or YAML</CardDescription></div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setSel(null); setText(JSON.stringify(meta?.example_library, null, 2)); }}><Sparkles className="h-4 w-4" />Example schema</Button>
            <label className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-lg border border-white/15 px-3 text-xs font-medium text-slate-200 hover:border-violet-400/50 hover:bg-violet-500/10"><FileUp className="h-4 w-4" />Choose file
              <input type="file" accept=".json,.yaml,.yml" className="hidden" onChange={async (e) => { const f = e.target.files?.[0]; if (f) setText(await f.text()); }} /></label>
          </div></CardHeader>
          <CardContent><Textarea rows={22} className="font-mono text-xs leading-relaxed" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} placeholder="Paste the library content or choose a file…" />
            <div className="mt-4 flex items-center gap-3"><Button disabled={!text.trim() || !can("operator")} onClick={save} title={can("operator") ? "" : "Operator role required"}><Save className="h-4 w-4" />Validate and save</Button>
              <span className="text-xs text-slate-500">An invalid library is never saved; each record's SHA-256 digest is written to the run evidence. For indirect tests add <code className="text-slate-400">documents</code> and <code className="text-slate-400">delivery</code> (inline/ingest) to the case.</span></div>
          </CardContent></Card>
      </div>
      </TabsContent>
      <TabsContent value="starter">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <p className="max-w-2xl text-sm text-slate-400"><b className="text-slate-200">10 ready-made templates</b> representing the OWASP Top 10 for LLM Applications (2025) categories. The contents are basic-level quality probes; not a certificate. After import they appear under “My libraries” and can be scanned with one click from the “OWASP Compliance” page.</p>
          {can("operator") && <div className="flex gap-2">
            <Button variant="secondary" disabled={!!busy} onClick={() => importTpl({ combined: true }, "combined")}><Package className="h-4 w-4" />{busy === "combined" ? "…" : "Combined kit (15 cases)"}</Button>
            <Button disabled={!!busy} onClick={() => importTpl({}, "all")}><Download className="h-4 w-4" />{busy === "all" ? "…" : "Import all"}</Button></div>}
        </div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {tpl?.templates.map((t: any, i: number) => (
            <Card key={t.id} className="flex flex-col"><CardContent className="flex flex-1 flex-col p-5">
              <div className="flex items-start justify-between"><span className="font-mono text-lg font-semibold text-white">{t.code}</span><Badge tone={t.coverage === "limited" ? "amber" : "green"}>{t.coverage === "limited" ? "limited coverage" : "direct test"}</Badge></div>
              <div className="mt-1 text-[15px] font-semibold text-slate-100">{t.name_en}</div>
              <p className="mt-2 flex-1 text-xs leading-relaxed text-slate-400">{t.description}</p>
              <div className="mt-3 flex flex-wrap gap-1.5"><Badge tone="violet"><FileText className="h-3 w-3" />{t.cases} cases</Badge>
                {t.needs_documents && <Badge tone="blue">document feeding</Badge>}{t.needs_tool_attestation && <Badge tone="amber"><Wrench className="h-3 w-3" />test-environment attestation</Badge>}{t.needs_multimodal && <Badge tone="amber">scope: multimodal files</Badge>}{t.needs_campaign && <Badge tone="amber">scope: campaigns</Badge>}
                {t.attack_classes.map((a: string) => <Badge key={a} tone="neutral">{meta?.attack_classes?.find((c: any) => c.id === a)?.label || a}</Badge>)}</div>
              <div className="mt-4 flex items-center justify-between"><span className="font-mono text-[10px] text-slate-600">{t.sha256.slice(0, 12)}… · v{t.version}</span>
                <Button size="sm" variant="outline" disabled={!!busy || !can("operator")} onClick={() => importTpl({ ids: [t.id] }, t.id)}><Download className="h-3.5 w-3.5" />{busy === t.id ? "…" : "Import"}</Button></div>
            </CardContent></Card>))}
        </div>
        {tpl?.advanced?.length > 0 && <>
          <div className="mb-3 mt-8"><h3 className="text-sm font-semibold text-slate-100">Advanced examples</h3>
            <p className="mt-1 max-w-2xl text-xs text-slate-400">Demonstrations of multi-step features against the bundled demo target: a fake tool sandbox, a Crescendo conversation, a Markdown image leak, agent identity probes, PLAGUE / PersonaTeaming, a multimodal carrier, an agentic tool chain, a knowledge map and a multi-session campaign ladder. They are separate from the OWASP kit. Tool cases need the scope's test-environment attestation and streaming off.</p></div>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{tpl.advanced.map((t: any) => (
            <Card key={t.id} className="flex flex-col"><CardContent className="flex flex-1 flex-col p-5">
              <div className="text-[15px] font-semibold text-slate-100">{t.name.replace("Advanced example - ", "")}</div>
              <p className="mt-2 flex-1 text-xs leading-relaxed text-slate-400">{t.description}</p>
              <div className="mt-3 flex flex-wrap gap-1.5">{t.features.map((x: string) => <Badge key={x} tone="violet">{x}</Badge>)}{t.needs_tool_attestation && <Badge tone="amber"><Wrench className="h-3 w-3" />test-environment attestation</Badge>}</div>
              <div className="mt-4 flex items-center justify-between"><span className="font-mono text-[10px] text-slate-600">{t.sha256.slice(0, 12)}… · v{t.version}</span>
                <Button size="sm" variant="outline" disabled={!!busy || !can("operator")} onClick={() => importTpl({ ids: [t.id] }, t.id)}><Download className="h-3.5 w-3.5" />{busy === t.id ? "…" : "Import"}</Button></div>
            </CardContent></Card>))}</div></>}
        <p className="mt-4 flex items-center gap-2 text-xs text-slate-500"><ShieldCheck className="h-3.5 w-3.5" />Templates only run for the attack classes your signed scope allows; the rest stay “Not tested” in the matrix.</p>
      </TabsContent>
      </Tabs>
    </>
  );
}
