import type { Config } from "tailwindcss";
import animate from "tailwindcss-animate";

const v = (name: string) => `rgb(var(--c-${name}) / <alpha-value>)`;
const STEPS = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
const scale = (fam: string) => Object.fromEntries(STEPS.map((s) => [s, v(`${fam}-${s}`)]));

export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-geist-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono Variable'", "var(--font-geist-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        // Every scale points at a CSS variable (app/theme-colors.css) so html.light can flip it without touching components.
        // slate uses calmer zinc values; indigo is a refined iris; both are defined there.
        ...Object.fromEntries(["slate", "indigo", "amber", "violet", "emerald", "rose", "red", "sky", "orange", "blue"].map((f) => [f, scale(f)])),
        white: v("white"), black: v("black"),
        // fixed white for text that sits on a solid colour (primary/danger buttons, logo, avatar): never flips
        snow: "#ffffff",
        // surfaces: deep ink in dark mode, white/near-white in light mode
        navy: { 950: v("navy-950"), 900: v("navy-900"), 800: v("navy-800"), 700: v("navy-700") },
        panel: v("panel"), sidebar: v("sidebar"),
        void: "#0a0b11",
        ink: { DEFAULT: "#0c0d14", raised: "#11131c", line: "rgba(255,255,255,0.07)" },
        accent: { DEFAULT: "#8e92ff", soft: "#b4b7ff", deep: "#6a6fe6" },
        neon: { violet: "#8b5cf6", blue: "#3b82f6", cyan: "#22d3ee", pink: "#ec4899" },
      },
      boxShadow: {
        glass: "var(--sh-glass)",
        glow: "0 0 24px -6px rgba(142,146,255,.5)", "glow-lg": "0 0 44px -10px rgba(142,146,255,.55)", "glow-blue": "0 0 24px -6px rgba(59,130,246,.4)",
        "glow-red": "0 0 20px -6px rgba(239,68,68,.5)",
        pill: "var(--sh-pill)",
        card3d: "var(--sh-card3d)",
      },
      keyframes: {
        shimmer: { "100%": { transform: "translateX(100%)" } },
        float: { "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-6px)" } },
        blink: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.15" } },
        pulseDot: { "0%": { transform: "scale(1)", opacity: ".75" }, "70%,100%": { transform: "scale(2.6)", opacity: "0" } },
        pulseRing: { "0%": { boxShadow: "0 0 0 0 rgba(52,211,153,.5)" }, "100%": { boxShadow: "0 0 0 8px rgba(52,211,153,0)" } },
      },
      animation: { float: "float 6s ease-in-out infinite", blink: "blink 1.1s steps(2,start) infinite", "pulse-ring": "pulseRing 1.8s ease-out infinite", "pulse-dot": "pulseDot 1.8s cubic-bezier(.2,.6,.3,1) infinite" },
    },
  },
  plugins: [animate],
} satisfies Config;
