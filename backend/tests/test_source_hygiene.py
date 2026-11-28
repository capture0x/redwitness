"""Source hygiene: no literal invisible or text-direction characters anywhere in the code ("Trojan Source", CVE-2021-42574).
Code that needs such characters (detectors, test inputs) must write them as escapes like \\u202e, so a reviewer sees exactly what is there."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIRS = ("backend/llm_redteam", "backend/tests", "backend/main.py", "frontend/app", "frontend/components", "frontend/lib", "frontend/e2e", "sandbox", "runner", "scripts")
SUFFIXES = {".py", ".ts", ".tsx", ".mjs", ".js", ".sh", ".json", ".yml", ".yaml"}
BAD = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")


def test_no_invisible_or_bidi_characters_in_source():
    hits = []
    for d in DIRS:
        base = ROOT / d
        for p in ([base] if base.is_file() else base.rglob("*")):
            if p.is_file() and p.suffix in SUFFIXES and "node_modules" not in p.parts and ".next" not in p.parts:
                for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    if BAD.search(line):
                        hits.append(f"{p.relative_to(ROOT)}:{n}")
    assert hits == [], f"write these characters as escapes (\\uXXXX): {hits[:10]}"
