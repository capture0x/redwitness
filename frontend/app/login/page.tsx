"use client";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Lock, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

export default function Login() {
  const router = useRouter();
  const [user, setUser] = useState("admin");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api("/auth/status").then((s) => { if (s.authenticated) router.replace("/"); else setProblem(s.problem); }).catch(() => {}); }, [router]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null);
    try { await api("/auth/login", { method: "POST", body: JSON.stringify({ username: user, password: pw }) }); router.replace("/"); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden p-6">
      <div className="grid-bg pointer-events-none absolute inset-0 opacity-70" />
      <motion.form onSubmit={submit} initial={{ opacity: 0, y: 24, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={{ duration: 0.5 }} className="glass relative w-full max-w-sm rounded-3xl p-8">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-4 grid h-14 w-14 animate-float place-items-center rounded-2xl bg-gradient-to-br from-violet-500 to-blue-500 shadow-glow"><Sparkles className="h-7 w-7 text-snow" /></div>
          <h1 className="text-gradient text-2xl font-semibold">AIVeritX</h1>
          <p className="mt-1 text-sm text-slate-400">AI Orchestration &amp; Test Platform</p>
        </div>
        {problem && <div className="mb-4 flex gap-2 rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 text-xs text-amber-200"><ShieldAlert className="h-4 w-4 shrink-0" />{problem}</div>}
        {err && <div className="mb-4 rounded-xl border border-red-400/30 bg-red-500/10 p-3 text-xs text-red-200">{err}</div>}
        <Label>Username</Label>
        <Input autoComplete="username" value={user} onChange={(e) => setUser(e.target.value)} className="mb-4" />
        <Label>Password</Label>
        <Input type="password" autoFocus autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
        <Button type="submit" className="mt-5 w-full" size="lg" disabled={busy || !pw || !user}><Lock className="h-4 w-4" />{busy ? "Signing in…" : "Sign in"}</Button>
        <p className="mt-4 text-center text-[11px] text-slate-500">Sessions last 8 hours. Failed attempts are locked out and recorded.</p>
      </motion.form>
    </div>
  );
}
