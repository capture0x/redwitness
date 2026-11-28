/**
 * API requests go to the same origin (the browser only talks to the UI; no CORS needed, the cookie stays on the same origin).
 * The backend address is fixed at BUILD time: 127.0.0.1:8000 locally, http://backend:8000 in Docker (build arg REDWITNESS_API).
 */
const API = process.env.REDWITNESS_API || "http://127.0.0.1:8000";
const DEV = process.env.NODE_ENV !== "production";

/**
 * Security headers for every page. Next.js and the theme boot script use inline scripts, so scripts need 'unsafe-inline'; the policy still
 * blocks framing (clickjacking), plugins, <base> hijacking, form posts and network requests to any other origin (no data can leave the page),
 * and loads nothing from third parties. `next dev` additionally needs eval for hot reload.
 */
const CSP = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${DEV ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self'${DEV ? " ws: wss:" : ""}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");
const SECURITY_HEADERS = [
  { key: "Content-Security-Policy", value: CSP },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
];

export default {
  reactStrictMode: true,
  poweredByHeader: false,        // no "X-Powered-By: Next.js"
  output: "standalone",          // small, self-contained runtime output for Docker
  async rewrites() { return [{ source: "/api/:path*", destination: `${API}/api/:path*` }]; },
  async headers() { return [{ source: "/:path*", headers: SECURITY_HEADERS }]; },
};
