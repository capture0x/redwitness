/**
 * API requests go to the same origin (the browser only talks to the UI; no CORS needed, the cookie stays on the same origin).
 * The backend address is fixed at BUILD time: 127.0.0.1:8000 locally, http://backend:8000 in Docker (build arg AIVERITX_API).
 */
const API = process.env.AIVERITX_API || "http://127.0.0.1:8000";
export default {
  reactStrictMode: true,
  output: "standalone",          // small, self-contained runtime output for Docker
  async rewrites() { return [{ source: "/api/:path*", destination: `${API}/api/:path*` }]; },
};
