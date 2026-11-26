"use client";
import * as React from "react";
import * as D from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

export const Dialog = D.Root;
export const DialogTrigger = D.Trigger;
export const DialogClose = D.Close;
export const DialogContent = ({ className, children, ...p }: React.ComponentProps<typeof D.Content>) => (
  <D.Portal>
    <D.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm data-[state=open]:animate-in data-[state=open]:fade-in-0" />
    <D.Content className={cn("glass fixed left-1/2 top-1/2 z-50 max-h-[88vh] w-[min(760px,94vw)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-2xl bg-navy-900/90 p-6 data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95", className)} {...p}>
      {children}
      <D.Close className="absolute right-4 top-4 rounded-lg p-1 text-slate-400 hover:bg-white/10 hover:text-white"><X className="h-4 w-4" /></D.Close>
    </D.Content>
  </D.Portal>
);
export const DialogTitle = ({ className, ...p }: React.ComponentProps<typeof D.Title>) => <D.Title className={cn("text-lg font-semibold text-white", className)} {...p} />;
export const DialogDescription = ({ className, ...p }: React.ComponentProps<typeof D.Description>) => <D.Description className={cn("mt-1 text-sm text-slate-400", className)} {...p} />;
