import Link from "next/link";
import type { LucideIcon } from "lucide-react";
import { Button } from "./ui/button";

/** "What should I do now?" screen for a page with no data yet. Pass `href` or `onClick` for the main action. */
export default function EmptyState({ icon: Icon, title, text, action, href, onClick, secondary, testId }: {
  icon: LucideIcon; title: string; text: string; action?: string; href?: string; onClick?: () => void;
  secondary?: { label: string; href: string }; testId?: string;
}) {
  return (
    <div data-testid={testId ?? "empty-state"} className="glass flex flex-col items-center rounded-2xl px-6 py-14 text-center">
      <div className="mb-4 grid h-14 w-14 place-items-center rounded-2xl bg-gradient-to-br from-indigo-400/25 to-violet-500/15 text-indigo-200 ring-1 ring-inset ring-white/10"><Icon className="h-6 w-6" /></div>
      <h3 className="text-[15px] font-semibold text-white">{title}</h3>
      <p className="mt-1.5 max-w-md text-[13px] leading-relaxed text-slate-400">{text}</p>
      {action && (
        <div className="mt-5 flex flex-wrap items-center justify-center gap-2.5">
          {href ? <Link href={href}><Button>{action}</Button></Link> : <Button onClick={onClick}>{action}</Button>}
          {secondary && <Link href={secondary.href}><Button variant="ghost">{secondary.label}</Button></Link>}
        </div>
      )}
    </div>
  );
}
