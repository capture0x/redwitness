"use client";
import { motion, useReducedMotion } from "framer-motion";

/** Slow, soft "nebula" mesh behind the whole app: a few huge blurred colour fields (violet, deep navy, a trace of teal) drifting very slowly. */
const BLOBS = [
  { c: "rgba(124,92,255,.20)", s: 760, x: ["-8%", "6%", "-4%"], y: ["-12%", "4%", "-8%"], at: { left: "-10%", top: "-18%" }, d: 46 },
  { c: "rgba(37,52,140,.38)", s: 900, x: ["4%", "-8%", "2%"], y: ["6%", "-6%", "10%"], at: { right: "-18%", top: "6%" }, d: 58 },
  { c: "rgba(34,211,238,.05)", s: 640, x: ["-4%", "10%", "0%"], y: ["8%", "-8%", "6%"], at: { left: "30%", bottom: "-24%" }, d: 52 },
  { c: "rgba(168,85,247,.11)", s: 560, x: ["6%", "-6%", "4%"], y: ["-6%", "8%", "-4%"], at: { right: "12%", bottom: "4%" }, d: 64 },
];

export default function AuroraBackground() {
  const still = useReducedMotion();
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-[var(--bg)]">
      {BLOBS.map((b, i) => (
        <motion.div key={i} className="absolute rounded-full blur-[110px]" style={{ opacity: "var(--aurora-opacity)", width: b.s, height: b.s, background: `radial-gradient(circle at 50% 50%, ${b.c}, transparent 68%)`, ...b.at }}
          animate={still ? undefined : { x: b.x, y: b.y, scale: [1, 1.12, 0.96, 1] }} transition={{ duration: b.d, repeat: Infinity, repeatType: "mirror", ease: "easeInOut" }} />
      ))}
      <div className="absolute inset-0 opacity-[0.5]" style={{ background: "radial-gradient(ellipse at 50% 0%, transparent 40%, var(--vignette) 100%)" }} />
      <div className="absolute inset-0 opacity-[0.035] mix-blend-overlay" style={{ backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")" }} />
    </div>
  );
}
