"use client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

/** One shared client: identical polls from several components are de-duplicated and refetches never blank the screen. */
export default function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(() => new QueryClient({
    defaultOptions: { queries: { staleTime: 1500, retry: 1, refetchOnWindowFocus: false, refetchIntervalInBackground: false } },
  }));
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
