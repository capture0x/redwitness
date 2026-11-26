import * as React from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { InfoTip } from "./help";

const field = "w-full rounded-xl border border-white/10 bg-white/[0.04] px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 transition focus:border-violet-400/60 focus:outline-none focus:ring-2 focus:ring-violet-500/25 disabled:opacity-50";
export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, ref) => <input ref={ref} className={cn(field, className)} {...p} />);
Input.displayName = "Input";
export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(({ className, ...p }, ref) => <textarea ref={ref} className={cn(field, "resize-y", className)} {...p} />);
Textarea.displayName = "Textarea";
export const NativeSelect = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(({ className, children, ...p }, ref) => (
  <div className="relative">
    <select ref={ref} className={cn(field, "appearance-none pr-10 [&>option]:bg-panel [&>option]:text-slate-100", className)} {...p}>{children}</select>
    <ChevronDown className="pointer-events-none absolute right-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
  </div>
));
NativeSelect.displayName = "NativeSelect";
export const Label = ({ className, help, children, ...p }: React.LabelHTMLAttributes<HTMLLabelElement> & { help?: string }) => (
  <label className={cn("mb-1.5 text-xs font-medium text-slate-400", help ? "flex items-center gap-1.5" : "block", className)} {...p}>{children}{help && <InfoTip text={help} />}</label>
);
export const Hint = ({ className, ...p }: React.HTMLAttributes<HTMLParagraphElement>) => <p className={cn("mt-1.5 text-xs text-slate-500", className)} {...p} />;
