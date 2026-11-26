"use client";
import { animate, motion, useMotionValue, useTransform } from "framer-motion";
import { useEffect } from "react";

export const Fade = ({ children, delay = 0, className }: { children: React.ReactNode; delay?: number; className?: string }) => (
  <motion.div className={className} initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45, delay, ease: [0.22, 1, 0.36, 1] }}>{children}</motion.div>
);
export const Stagger = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <motion.div className={className} initial="hide" animate="show" variants={{ show: { transition: { staggerChildren: 0.06 } }, hide: {} }}>{children}</motion.div>
);
export const Item = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <motion.div className={className} variants={{ hide: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0, transition: { duration: 0.4 } } }}>{children}</motion.div>
);
export function Count({ to, className, fmt }: { to: number; className?: string; fmt?: (n: number) => string }) {
  const v = useMotionValue(0);
  const txt = useTransform(v, (n) => (fmt ? fmt(Math.round(n)) : Math.round(n).toLocaleString("en-US")));
  useEffect(() => { const c = animate(v, to, { duration: 1.1, ease: "easeOut" }); return () => c.stop(); }, [to, v]);
  return <motion.span className={className}>{txt}</motion.span>;
}
