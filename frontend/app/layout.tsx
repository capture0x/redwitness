import "./globals.css";
import "@fontsource-variable/jetbrains-mono";
import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import Providers from "@/components/Providers";
import Shell from "@/components/Shell";
import { THEME_BOOT } from "@/lib/theme";

export const metadata: Metadata = { title: "AIVeritX - AI Orchestration & Test Platform" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`light ${GeistSans.variable} ${GeistMono.variable}`} suppressHydrationWarning>
      {/* sets dark/light on <html> before the first paint (choice stored in this browser) */}
      <head><script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} /></head>
      <body><Providers><Shell>{children}</Shell></Providers></body>
    </html>
  );
}
