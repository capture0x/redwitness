"use client";
import * as React from "react";
import * as T from "@radix-ui/react-tabs";
import { cn } from "@/lib/utils";

export const Tabs = T.Root;
export const TabsList = ({ className, ...p }: React.ComponentProps<typeof T.List>) => <T.List className={cn("inline-flex gap-1 rounded-xl border border-white/10 bg-white/[0.03] p-1", className)} {...p} />;
export const TabsTrigger = ({ className, ...p }: React.ComponentProps<typeof T.Trigger>) => (
  <T.Trigger className={cn("rounded-lg px-3 py-1.5 text-xs font-medium text-slate-400 transition data-[state=active]:bg-white/10 data-[state=active]:text-white data-[state=active]:shadow-glow", className)} {...p} />
);
export const TabsContent = ({ className, ...p }: React.ComponentProps<typeof T.Content>) => <T.Content className={cn("mt-3 focus-visible:outline-none", className)} {...p} />;
