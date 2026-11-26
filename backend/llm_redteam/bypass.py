"""
Defense-bypass test techniques (message transforms). The engine holds NO attack wording: the library supplies the template text that
explains to the target how to read the transformed message. Only reversible, deterministic encodings live here, so a run is reproducible
and the replay verification sees byte-identical messages.

  base64 | rot13 | hex     the operator's message is encoded; the library template says how to decode it
  homoglyph                Latin letters replaced by look-alike Unicode letters (no template wording required, optional)
  split                    one message is cut into N parts delivered over N turns (instruction splitting)
  language_switch          a label only: the wording is written in another language by the library author or the Attacker agent
"""
import base64
import codecs
from dataclasses import dataclass

TECHNIQUES = ("base64", "rot13", "hex", "homoglyph", "split", "language_switch")
APPLY_TO = ("first", "last", "all")
MAX_PARTS = 8
MAX_TEMPLATE = 2000

HOMOGLYPHS = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у", "i": "і", "s": "ѕ", "j": "ј",
              "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "K": "К", "M": "М", "O": "О", "P": "Р", "T": "Т", "X": "Х"}


class BypassError(ValueError):
    pass


@dataclass(frozen=True)
class Bypass:
    technique: str
    template: str = ""          # from the library; must contain {payload} (split: {part} {index} {total})
    parts: int = 3              # split only
    apply_to: str = "first"


def _encode(technique: str, text: str) -> str:
    if technique == "base64":
        return base64.b64encode(text.encode()).decode()
    if technique == "hex":
        return text.encode().hex()
    if technique == "rot13":
        return codecs.encode(text, "rot13")
    if technique == "homoglyph":
        return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)
    return text


def _split(text: str, n: int) -> list[str]:
    words = text.split()
    n = max(1, min(n, len(words)))
    size, extra = divmod(len(words), n)
    out, i = [], 0
    for k in range(n):
        j = i + size + (1 if k < extra else 0)
        out.append(" ".join(words[i:j]))
        i = j
    return out


def validate(technique: str, template: str, parts: int, apply_to: str) -> Bypass:
    if technique not in TECHNIQUES:
        raise BypassError(f"bypass_technique must be one of {TECHNIQUES}")
    if apply_to not in APPLY_TO:
        raise BypassError(f"bypass.apply_to must be one of {APPLY_TO}")
    if len(template) > MAX_TEMPLATE or "\x00" in template:
        raise BypassError("bypass.template is too long or contains NUL")
    if technique in ("base64", "rot13", "hex") and "{payload}" not in template:
        raise BypassError(f"bypass.template must contain {{payload}} for {technique} (the library explains how to read the encoding)")
    if technique == "split":
        if not isinstance(parts, int) or isinstance(parts, bool) or not 2 <= parts <= MAX_PARTS:
            raise BypassError(f"bypass.parts must be an integer between 2 and {MAX_PARTS}")
        if "{part}" not in template:
            raise BypassError("bypass.template for split must contain {part} (and may use {index} and {total})")
    if technique == "homoglyph" and template and "{payload}" not in template:
        raise BypassError("bypass.template, when given, must contain {payload}")
    return Bypass(technique, template, parts if technique == "split" else 3, apply_to)


def _one(b: Bypass, text: str) -> list[str]:
    if b.technique == "language_switch":
        return [text]
    if b.technique == "split":
        ps = _split(text, b.parts)
        return [b.template.replace("{part}", p).replace("{index}", str(i)).replace("{total}", str(len(ps))) for i, p in enumerate(ps, 1)]
    enc = _encode(b.technique, text)
    return [b.template.replace("{payload}", enc) if b.template else enc]


def apply(b: Bypass | None, messages: list[str]) -> list[str]:
    """Transforms the chosen message(s). Pure and deterministic."""
    if b is None or not messages:
        return list(messages)
    idx = {"first": [0], "last": [len(messages) - 1], "all": list(range(len(messages)))}[b.apply_to]
    out: list[str] = []
    for i, m in enumerate(messages):
        out.extend(_one(b, m) if i in idx else [m])
    return out
