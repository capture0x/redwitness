"use client";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import AuroraBackground from "./AuroraBackground";
import Sidebar from "./Sidebar";
import { TooltipProvider } from "./ui/misc";
import { api } from "@/lib/api";
import { MeContext, RANK, Role, routeRole, ROLE_LABEL } from "@/lib/me";
import { ShieldOff } from "lucide-react";

/** Session gate: redirects to /login when not signed in; the sidebar is not shown on the login page. */
export default function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const router = useRouter();
  const [ok, setOk] = useState<boolean | null>(null);
  const [me, setMe] = useState<{ username: string; role: Role } | null>(null);

  useEffect(() => {
    let alive = true;
    api("/auth/status").then((s) => { if (!alive) return; setOk(!!s.authenticated); setMe(s.user ?? null); if (!s.authenticated && path !== "/login") router.replace("/login"); }).catch(() => { if (!alive) return; setOk(false); if (path !== "/login") router.replace("/login"); });
    const un = () => { setOk(false); router.replace("/login"); };
    window.addEventListener("redwitness:unauthorized", un);
    return () => { alive = false; window.removeEventListener("redwitness:unauthorized", un); };
  }, [path, router]);

  if (path === "/login") return <TooltipProvider><AuroraBackground />{children}</TooltipProvider>;
  const can = (need: Role) => !!me && RANK[me.role] >= RANK[need];
  if (!ok) return <div className="flex h-screen items-center justify-center text-sm text-slate-500">Verifying session…</div>;
  const need = routeRole(path);
  return (
    <TooltipProvider><MeContext.Provider value={{ me, can }}>
      <AuroraBackground />
      <div className="flex h-screen">
        <Sidebar />
        <main className="relative flex-1 overflow-y-auto">
          <div className="grid-bg pointer-events-none absolute inset-x-0 top-0 h-80 opacity-50" />
          <AnimatePresence mode="wait">
            <motion.div key={path} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.28 }} className="relative mx-auto max-w-[1360px] px-12 py-12">
              {can(need) ? children : (
                <div className="glass mx-auto mt-24 max-w-md rounded-2xl p-10 text-center">
                  <ShieldOff className="mx-auto mb-3 h-10 w-10 text-amber-300" />
                  <h2 className="text-lg font-semibold text-white">You do not have access to this page</h2>
                  <p className="mt-1 text-sm text-slate-400">This page requires at least the “{ROLE_LABEL[need]}” role (your role: {me ? ROLE_LABEL[me.role] : "-"}).</p>
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </MeContext.Provider></TooltipProvider>
  );
}
