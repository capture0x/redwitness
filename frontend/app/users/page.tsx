"use client";
import { useState } from "react";
import { KeyRound, ShieldCheck, UserCheck, UserPlus, UserX } from "lucide-react";
import { api, fmtDate, usePoll } from "@/lib/api";
import PageHeader, { Notice } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Hint, Input, Label, NativeSelect } from "@/components/ui/input";
import { ROLE_LABEL, useMe } from "@/lib/me";

const ROLE_DESC: Record<string, string> = {
  viewer: "Read only: dashboard, runs, findings, PDF/CSV reports.",
  operator: "Viewer + start/stop tests, library upload, audit records.",
  admin: "Full control: scope signing/revocation, settings, user management.",
};
const TONE: Record<string, any> = { admin: "violet", operator: "blue", viewer: "neutral" };

export default function UsersPage() {
  const { me } = useMe();
  const { data: users, reload } = usePoll(() => api("/users"), 0);
  const [f, setF] = useState({ username: "", password: "", role: "viewer" });
  const [reset, setReset] = useState<{ username: string; password: string } | null>(null);
  const [msg, setMsg] = useState<{ t: "green" | "red"; m: string } | null>(null);
  const act = async (fn: () => Promise<any>, ok: string) => { try { await fn(); setMsg({ t: "green", m: ok }); reload(); } catch (e: any) { setMsg({ t: "red", m: e.message }); } };
  return (
    <>
      <PageHeader title="Users" sub="Role-based access control. Role changes and deactivation take effect immediately; the last active admin cannot be demoted." />
      {msg && <Notice tone={msg.t}>{msg.m}</Notice>}
      <div className="mb-6 grid gap-3 md:grid-cols-3">
        {(["viewer", "operator", "admin"] as const).map((r) => (
          <Card key={r} className="p-4"><div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-violet-300" /><Badge tone={TONE[r]}>{ROLE_LABEL[r]}</Badge></div><p className="mt-2 text-xs text-slate-400">{ROLE_DESC[r]}</p></Card>))}
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2 overflow-hidden"><CardHeader><div><CardTitle>Accounts</CardTitle><CardDescription>{users?.length ?? 0} users</CardDescription></div></CardHeader>
          <CardContent className="p-0 pt-3">
            <table className="w-full text-sm"><thead><tr className="border-b border-white/[0.07] text-left text-[11px] uppercase tracking-wider text-slate-500"><th className="px-5 py-2">User</th><th>Role</th><th>Last sign-in</th><th className="pr-5 text-right">Actions</th></tr></thead>
              <tbody>{users?.map((u: any) => (
                <tr key={u.username} className="border-b border-white/[0.05]">
                  <td className="px-5 py-3"><span className="font-medium text-white">{u.username}</span>{u.username === me?.username && <span className="ml-2 text-xs text-slate-500">(you)</span>}{!u.active && <Badge tone="red" className="ml-2">deactivated</Badge>}</td>
                  <td className="pr-3"><NativeSelect value={u.role} className="h-9 py-1 text-xs" onChange={(e) => act(() => api(`/users/${u.username}`, { method: "PATCH", body: JSON.stringify({ role: e.target.value }) }), `${u.username} role updated.`)}>
                    {Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</NativeSelect></td>
                  <td className="text-xs text-slate-500">{fmtDate(u.last_login)}</td>
                  <td className="pr-5 text-right"><div className="flex justify-end gap-1.5">
                    <Button variant="ghost" size="sm" onClick={() => setReset({ username: u.username, password: "" })}><KeyRound className="h-3.5 w-3.5" />Password</Button>
                    <Button variant="outline" size="sm" onClick={() => act(() => api(`/users/${u.username}`, { method: "PATCH", body: JSON.stringify({ active: !u.active }) }), u.active ? `${u.username} deactivated.` : `${u.username} activated.`)}>
                      {u.active ? <><UserX className="h-3.5 w-3.5" />Deactivate</> : <><UserCheck className="h-3.5 w-3.5" />Activate</>}</Button></div></td>
                </tr>))}</tbody></table>
          </CardContent></Card>
        <Card><CardHeader><div><CardTitle>New user</CardTitle><CardDescription>Password of at least 12 characters</CardDescription></div><UserPlus className="h-4 w-4 text-slate-500" /></CardHeader>
          <CardContent className="space-y-4">
            <div><Label>Username</Label><Input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value.toLowerCase() })} placeholder="example.user" /><Hint>3-32 characters: a-z, 0-9, ., _, -</Hint></div>
            <div><Label>Password</Label><Input type="password" autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></div>
            <div><Label>Role</Label><NativeSelect value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>{Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</NativeSelect></div>
            <Button className="w-full" disabled={!f.username || f.password.length < 12} onClick={() => act(async () => { await api("/users", { method: "POST", body: JSON.stringify(f) }); setF({ username: "", password: "", role: "viewer" }); }, `${f.username} created.`)}><UserPlus className="h-4 w-4" />Create</Button>
          </CardContent></Card>
      </div>
      <Dialog open={!!reset} onOpenChange={(o) => !o && setReset(null)}>
        <DialogContent className="w-[min(440px,94vw)]">{reset && <>
          <DialogTitle>Reset password - {reset.username}</DialogTitle><DialogDescription>All of the user's current sessions will be closed.</DialogDescription>
          <div className="mt-4"><Label>New password (at least 12 characters)</Label><Input type="password" autoComplete="new-password" value={reset.password} onChange={(e) => setReset({ ...reset, password: e.target.value })} /></div>
          <div className="mt-5 flex justify-end"><Button disabled={reset.password.length < 12} onClick={() => act(async () => { await api(`/users/${reset.username}/password`, { method: "POST", body: JSON.stringify({ password: reset.password }) }); setReset(null); }, "Password reset.")}>Reset</Button></div></>}
        </DialogContent></Dialog>
    </>
  );
}
