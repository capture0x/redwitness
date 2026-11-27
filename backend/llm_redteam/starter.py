"""OWASP LLM Top 10 starter kit: backend/starter_kit/owasp/*.json. Each file is a valid test library; they are also merged into one combined library."""
import json
from pathlib import Path

from . import owasp as owasp_mod
from .library import Library, LibraryError, parse_library

KIT_DIR = Path(__file__).resolve().parent.parent / "starter_kit" / "owasp"
ADV_DIR = KIT_DIR.parent / "advanced"
COMBINED_ID = "OWASP_ALL"
COMBINED_NAME = "OWASP LLM Top 10 - Starter Kit (all)"


def _files() -> list[Path]:
    return sorted(KIT_DIR.glob("LLM*.json"))


def template_text(tid: str) -> str:
    p = (ADV_DIR if tid.startswith("ADV_") else KIT_DIR) / f"{tid}.json"
    if tid == COMBINED_ID or "/" in tid or ".." in tid or not p.is_file():
        raise KeyError(tid)
    return p.read_text(encoding="utf-8")


def combined_text() -> str:
    """All template cases in one library. Deterministic (same content = same SHA-256)."""
    cases, version = [], "1.0.0"
    for f in _files():
        d = json.loads(f.read_text(encoding="utf-8"))
        version = d["library"]["version"]
        cases += d["cases"]
    lib = {"library": {"name": COMBINED_NAME, "version": version,
                       "description": "Basic quality probes representing the OWASP Top 10 for LLM Applications (2025) categories. Not a certificate."},
           "cases": cases}
    return json.dumps(lib, ensure_ascii=False, indent=1) + "\n"


def list_templates() -> list[dict]:
    out = []
    for f in _files():
        lib: Library = parse_library(f.read_text(encoding="utf-8"))          # every file is validated; a broken template is never served silently
        owasp_id = lib.cases[0].owasp_category
        cat = owasp_mod.BY_ID[owasp_id]
        out.append({"id": f.stem, "owasp_category": owasp_id, "code": cat["code"], "name": lib.name, "name_en": cat["en"],
                    "description": lib.description, "cases": len(lib.cases), "version": lib.version, "sha256": lib.sha256,
                    "coverage": cat["coverage"], "attack_classes": sorted({c.category for c in lib.cases}),
                    "needs_documents": any(c.documents for c in lib.cases),
                    "needs_tool_attestation": any(c.category == "tool_abuse" for c in lib.cases),
                    "needs_multimodal": any(c.media for c in lib.cases), "needs_campaign": any(c.campaign for c in lib.cases)})
    if len(out) != 10 or {t["owasp_category"] for t in out} != set(owasp_mod.BY_ID):
        raise LibraryError("starter kit incomplete: there must be one template for each of the 10 OWASP categories")
    return out


def list_advanced() -> list[dict]:
    """Advanced example libraries (tool sandbox, crescendo, markdown leak). Separate from the OWASP kit: they are demonstrations of the engine's multi-step
    features, not part of the basic OWASP probes (the combined kit does not include them)."""
    out = []
    for f in sorted(ADV_DIR.glob("ADV_*.json")):
        lib: Library = parse_library(f.read_text(encoding="utf-8"))
        out.append({"id": f.stem, "name": lib.name, "description": lib.description, "cases": len(lib.cases), "version": lib.version, "sha256": lib.sha256,
                    "owasp_category": lib.cases[0].owasp_category, "attack_classes": sorted({c.category for c in lib.cases}),
                    "features": sorted({"tool sandbox" for c in lib.cases if c.tools} | {"crescendo" for c in lib.cases if c.crescendo}
                                       | {"markdown leak" for c in lib.cases if "image" in c.turns[0].lower()}
                                       | {"agentic (ASI)" for c in lib.cases if c.asi_category}
                                       | {"multimodal carrier" for c in lib.cases if c.media} | {"agentic chain" for c in lib.cases if c.steps}
                                       | {"knowledge map" for c in lib.cases if c.nodes} | {"multi-session campaign" for c in lib.cases if c.campaign}
                                       | {"jailbreak techniques" for c in lib.cases if c.category == "jailbreak"}
                                       | {"adaptive " + c.adaptive.method for c in lib.cases if c.adaptive and c.adaptive.method != "rewrite"}),
                    "needs_tool_attestation": any(c.category == "tool_abuse" for c in lib.cases),
                    "needs_multimodal": any(c.media for c in lib.cases), "needs_campaign": any(c.campaign for c in lib.cases)})
    return out


QUICK_ID = "QUICK_SCAN"
NOT_IN_QUICK_SCAN = {"ADV_agentic", "ADV_plague_persona", "ADV_multimodal", "ADV_agentic_chain", "ADV_knowledge_map", "ADV_campaign_ladder"}
# opt-in: agent-specific, adaptive (Attacker LLM), file-sending (multimodal), mapping and multi-session examples
QUICK_NAME = "Quick scan: OWASP kit + advanced examples"


def quick_scan_text() -> str:
    """The library behind the one-screen quick scan: every OWASP starter case plus the advanced examples (tool sandbox, Crescendo, Markdown leak, jailbreak techniques).
    Deterministic, so the same content always has the same SHA-256. Cases whose attack class the signed scope does not allow are skipped at run start."""
    d = json.loads(combined_text())
    for f in sorted(ADV_DIR.glob("ADV_*.json")):
        if f.stem in NOT_IN_QUICK_SCAN:
            continue
        d["cases"] += json.loads(f.read_text(encoding="utf-8"))["cases"]
    ids = [c["id"] for c in d["cases"]]
    if len(ids) != len(set(ids)):
        raise LibraryError("quick scan library has duplicate case ids")
    d["library"] = {"name": QUICK_NAME, "version": d["library"]["version"],
                    "description": "All OWASP LLM Top 10 starter probes plus tool-abuse (fake tools), Crescendo, Markdown-leak and jailbreak-technique examples. Basic quality probes; not a certificate."}
    return json.dumps(d, ensure_ascii=False, indent=1) + "\n"
