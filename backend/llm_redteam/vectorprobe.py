"""
Vector store exposure test: READ-ONLY, allowlisted, credential-less requests to a vector database the signed scope authorizes.

The question is "can a stranger on the network read this store?". Requests carry no credentials on purpose. Only the exact (method, path) shapes below can be
sent, record sampling is fixed at 3 records per collection, nothing is ever written, updated or deleted, and every request goes through
Governor.authorize_probe (signed scope, address check, request/rate limits, kill switch). Results hold masked, truncated previews and embedding sizes only.
"""
import re
from urllib.parse import quote

import httpx

from .governor import Denied, Governor
from .scope import Endpoint
from .targets import pinned_client

CATEGORY = "vector_store_exposure"
SAMPLE_LIMIT, MAX_COLLECTIONS, MAX_BYTES, PREVIEW_CHARS = 3, 10, 1_000_000, 60
N = r"[A-Za-z0-9_.\-]{1,200}"
ALLOW: dict[str, list[tuple[str, re.Pattern]]] = {
    "chroma": [("GET", re.compile(p)) for p in (r"/api/v2/heartbeat", r"/api/v1/heartbeat", r"/api/v2/tenants/default_tenant/databases/default_database/collections",
                                                 r"/api/v1/collections", rf"/api/v2/tenants/default_tenant/databases/default_database/collections/{N}/count")]
              + [("POST", re.compile(rf"/api/v2/tenants/default_tenant/databases/default_database/collections/{N}/get"))],
    "qdrant": [("GET", re.compile(p)) for p in (r"/collections", rf"/collections/{N}")] + [("POST", re.compile(rf"/collections/{N}/points/scroll"))],
    "weaviate": [("GET", re.compile(p)) for p in (r"/v1/meta", r"/v1/schema", r"/v1/objects")],
}
SECRET = re.compile(r"(sk-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}|(?i:bearer)\s+\S{12,}|[A-Za-z0-9+/_\-]{32,})")
EMAIL, LONGNUM = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), re.compile(r"\d[\d\s\-]{7,}\d")


class ProbeRefused(Exception):
    pass


def mask_preview(v) -> tuple[str, bool]:
    s = v if isinstance(v, str) else str(v)
    s = " ".join(s.split())
    hit = bool(SECRET.search(s) or EMAIL.search(s) or LONGNUM.search(s))
    s = EMAIL.sub("[email]", SECRET.sub("[secret]", s))
    s = LONGNUM.sub("[number]", s)
    return s[:PREVIEW_CHARS] + ("…" if len(s) > PREVIEW_CHARS else ""), hit


class VectorProbe:
    def __init__(self, ep: Endpoint, gov: Governor, *, http: httpx.AsyncClient | None = None, timeout: float = 15.0):
        if ep.provider not in ALLOW:
            raise ProbeRefused("not a vector store endpoint")
        self.ep, self.gov, self.timeout = ep, gov, timeout
        self._http, self._own = http or pinned_client(ep.local), http is None
        self.base = ep.url.rstrip("/")
        self.requests = 0

    async def aclose(self):
        if self._own:
            await self._http.aclose()

    async def _req(self, method: str, path: str, body: dict | None = None, params: dict | None = None):
        """(status, json|None). Raises ProbeRefused when the (method, path) is not on the allowlist, Denied when the Governor refuses."""
        if not any(m == method and rx.fullmatch(path) for m, rx in ALLOW[self.ep.provider]):
            raise ProbeRefused(f"{method} {path} is not an allowed read-only probe")
        await self.gov.authorize_probe(self.ep.url, CATEGORY)
        self.requests += 1
        try:
            r = await self._http.request(method, self.base + path, json=body, params=params, headers={"accept": "application/json"}, timeout=self.timeout)
        except httpx.HTTPError as e:
            return None, {"error": type(e).__name__}
        data = None
        if r.status_code < 300 and len(r.content) <= MAX_BYTES:
            try:
                data = r.json()
            except ValueError:
                data = None
        return r.status_code, data

    # ---------------------------------------------------------------- per provider
    async def run(self) -> dict:
        out = {"kind": "vector", "provider": self.ep.provider, "reachable": False, "listable": False, "readable": False, "embeddings_readable": False,
               "collections": [], "findings": [], "stopped_reason": None}
        try:
            await getattr(self, "_" + self.ep.provider)(out)
        except Denied as d:
            out["stopped_reason"] = d.reason.value
        out["requests"] = self.requests
        return self._finish(out)

    def _note(self, out, sev, code, msg):
        out["findings"].append({"severity": sev, "code": code, "message": msg})

    def _record(self, out, name, count, previews, dims):
        sens = False
        masked = []
        for v in previews:
            m, h = mask_preview(v)
            masked.append(m)
            sens = sens or h
        out["collections"].append({"name": str(name)[:100], "count": count, "sampled": len(masked), "previews": masked, "sensitive_pattern": sens, "embedding_dims": dims})
        if masked:
            out["readable"] = True
        if dims:
            out["embeddings_readable"] = True

    async def _chroma(self, out):
        base = "/api/v2/tenants/default_tenant/databases/default_database/collections"
        st, _ = await self._req("GET", "/api/v2/heartbeat")
        out["reachable"] = st is not None
        st, cols = await self._req("GET", base)
        if st is None or st >= 300 or not isinstance(cols, list):
            return
        out["listable"] = True
        for c in cols[:MAX_COLLECTIONS]:
            cid, name = quote(str(c.get("id", "")), safe=""), c.get("name", "?")
            if not re.fullmatch(N, cid):
                continue
            _, cnt = await self._req("GET", f"{base}/{cid}/count")
            st2, g = await self._req("POST", f"{base}/{cid}/get", {"limit": SAMPLE_LIMIT, "include": ["documents", "metadatas", "embeddings"]})
            docs = (g or {}).get("documents") or []
            emb = (g or {}).get("embeddings")
            dims = len(emb[0]) if isinstance(emb, list) and emb and isinstance(emb[0], list) else None
            self._record(out, name, cnt if isinstance(cnt, int) else None, [d for d in docs if d][:SAMPLE_LIMIT], dims)

    async def _qdrant(self, out):
        st, cols = await self._req("GET", "/collections")
        out["reachable"] = st is not None
        names = [c.get("name") for c in ((cols or {}).get("result") or {}).get("collections", [])] if st and st < 300 else None
        if names is None:
            return
        out["listable"] = True
        for n in names[:MAX_COLLECTIONS]:
            if not isinstance(n, str) or not re.fullmatch(N, n):
                continue
            _, info = await self._req("GET", f"/collections/{quote(n, safe='')}")
            cnt = ((info or {}).get("result") or {}).get("points_count")
            _, sc = await self._req("POST", f"/collections/{quote(n, safe='')}/points/scroll", {"limit": SAMPLE_LIMIT, "with_payload": True, "with_vector": True})
            pts = (((sc or {}).get("result") or {}).get("points")) or []
            dims = next((len(p["vector"]) for p in pts if isinstance(p.get("vector"), list)), None)
            self._record(out, n, cnt if isinstance(cnt, int) else None, [str(p.get("payload"))[:300] for p in pts if p.get("payload")], dims)

    async def _weaviate(self, out):
        st, _ = await self._req("GET", "/v1/meta")
        out["reachable"] = st is not None
        st, sch = await self._req("GET", "/v1/schema")
        if st and st < 300 and isinstance(sch, dict):
            out["listable"] = True
        st, objs = await self._req("GET", "/v1/objects", params={"limit": SAMPLE_LIMIT})
        items = (objs or {}).get("objects") or [] if st and st < 300 else []
        if items:
            dims = next((len(o["vector"]) for o in items if isinstance(o.get("vector"), list)), None)
            self._record(out, "objects", (objs or {}).get("totalResults"), [str(o.get("properties"))[:300] for o in items[:SAMPLE_LIMIT]], dims)

    def _finish(self, out) -> dict:
        if out["readable"]:
            self._note(out, "critical", "VECTOR_RECORDS_READABLE", "Stored records can be read without credentials (previews in the result are masked and truncated).")
        if out["embeddings_readable"]:
            self._note(out, "high", "VECTOR_EMBEDDINGS_READABLE", "Embedding vectors can be read without credentials; embeddings can be inverted to approximate the source text.")
        if out["listable"]:
            self._note(out, "high", "VECTOR_COLLECTIONS_LISTABLE", "Collections / schema can be enumerated without credentials.")
        if any(c["sensitive_pattern"] for c in out["collections"]):
            self._note(out, "critical", "VECTOR_SENSITIVE_PATTERN", "Sampled records contain patterns that look like secrets, e-mail addresses or long numbers.")
        if out["reachable"] and not out["listable"] and not out["readable"]:
            self._note(out, "info", "VECTOR_PROTECTED", "The store answers but refused unauthenticated listing and reading.")
        if not out["reachable"]:
            self._note(out, "info", "VECTOR_UNREACHABLE", "No answer from the endpoint.")
        order = ["info", "low", "medium", "high", "critical"]
        top = max((f["severity"] for f in out["findings"]), key=order.index, default="info")
        out["risk"] = {"level": top if top != "info" else "low", "reasons": [f["message"] for f in out["findings"] if f["severity"] != "info"] or ["No unauthenticated exposure found."]}
        out["caveats"] = ["Read-only and credential-less by design: a protected result means unauthenticated access failed, not that authenticated access is safe.",
                          "At most 3 records per collection are sampled; previews are masked and truncated; nothing is written."]
        return out
