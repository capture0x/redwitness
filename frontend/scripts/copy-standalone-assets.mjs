// `output: "standalone"` builds a self-contained server in .next/standalone, but it does NOT copy the static assets
// (.next/static) or public/. Without them the pages load without JS and the app hangs on "Verifying session…".
// Runs automatically after `npm run build`. The Dockerfile does the same copy for the container image.
import { cpSync, existsSync, mkdirSync } from "node:fs";
const out = ".next/standalone";
if (!existsSync(out)) { console.error("postbuild: .next/standalone is missing (is output: 'standalone' set?)"); process.exit(1); }
mkdirSync(`${out}/.next`, { recursive: true });
cpSync(".next/static", `${out}/.next/static`, { recursive: true });
if (existsSync("public")) cpSync("public", `${out}/public`, { recursive: true });
console.log("postbuild: copied .next/static" + (existsSync("public") ? " and public" : "") + " into .next/standalone");
