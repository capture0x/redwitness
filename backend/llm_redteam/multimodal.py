"""
Multimodal CARRIER support. A library case of `type: multimodal` attaches image or audio files that the OPERATOR wrote into the (hashed) library.

  * The engine never creates, edits or "improves" a file: the bytes are sent exactly as the library holds them. The file is only a carrier.
  * Before anything is sent, a static pre-processing step looks at what the file really carries and records it as evidence:
      images : the text found by OCR (Tesseract, when installed) and the text in metadata (EXIF, PNG text chunks, JPEG comments)
      audio  : header facts and tag strings only. The speech itself is NOT transcribed (no speech-to-text here); this is stated in the report.
  * Canary check: if one of the operator's canary values appears in the text a file carries, the file is NOT sent (the canary would reach the target
    through the file and could no longer be told apart from a leak).
  * The scope must grant `multimodal_allowed`; the Governor refuses media otherwise.
"""
import base64
import binascii
import hashlib
import io
import re
import shutil
import subprocess
import wave
from dataclasses import dataclass

MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 3, 1_500_000, 3_000_000
MAX_PIXELS, MAX_AUDIO_SECONDS = 20_000_000, 60
FORMATS = {"png": ("image", "image/png"), "jpeg": ("image", "image/jpeg"), "wav": ("audio", "audio/wav"), "mp3": ("audio", "audio/mpeg")}
# A file costs tokens even though it is not text: the Governor is charged this many characters per file and request (a documented estimate).
COST_CHARS = {"image": 4000, "audio": 8000}
OCR_TIMEOUT = 20
MAX_TEXT = 4000
ANTHROPIC_KINDS = ("image",)


class MediaError(ValueError):
    pass


@dataclass(frozen=True)
class Media:
    name: str
    format: str
    data: bytes = b""
    declared_text: str = ""            # what the operator says the file shows/says (used only to report text that is NOT declared)

    @property
    def kind(self) -> str:
        return FORMATS[self.format][0]

    @property
    def mime(self) -> str:
        return FORMATS[self.format][1]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def _check_bytes(fmt: str, data: bytes, name: str) -> None:
    if fmt == "png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise MediaError(f"{name!r}: not a PNG file")
    if fmt == "jpeg" and not data.startswith(b"\xff\xd8\xff"):
        raise MediaError(f"{name!r}: not a JPEG file")
    if fmt == "wav" and not (data[:4] == b"RIFF" and data[8:12] == b"WAVE"):
        raise MediaError(f"{name!r}: not a WAV file")
    if fmt == "mp3" and not (data.startswith(b"ID3") or (len(data) > 2 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0)):
        raise MediaError(f"{name!r}: not an MP3 file")
    if fmt in ("png", "jpeg"):
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        try:
            with Image.open(io.BytesIO(data)) as im:
                im.verify()
            with Image.open(io.BytesIO(data)) as im:
                if im.width * im.height > MAX_PIXELS:
                    raise MediaError(f"{name!r}: the image is too large (more than {MAX_PIXELS} pixels)")
        except MediaError:
            raise
        except Exception:  # noqa: BLE001
            raise MediaError(f"{name!r}: the image could not be decoded") from None
    if fmt == "wav":
        try:
            with wave.open(io.BytesIO(data)) as w:
                if w.getframerate() and w.getnframes() / w.getframerate() > MAX_AUDIO_SECONDS:
                    raise MediaError(f"{name!r}: the audio is longer than {MAX_AUDIO_SECONDS} seconds")
        except MediaError:
            raise
        except Exception:  # noqa: BLE001
            raise MediaError(f"{name!r}: the WAV file could not be read") from None


def parse_media(raw) -> tuple[Media, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_FILES:
        raise MediaError(f"'media' must be a list of 1-{MAX_FILES} files")
    out, total, seen = [], 0, set()
    for m in raw:
        if not isinstance(m, dict) or set(m) - {"name", "format", "data_base64", "declared_text"}:
            raise MediaError("every media item must be an object with name, format, data_base64 and (optionally) declared_text")
        name, fmt, b64 = m.get("name"), m.get("format"), m.get("data_base64")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,60}", name) or name in seen:
            raise MediaError("media names must be unique, 1-60 characters of letters, digits, _ . -")
        seen.add(name)
        if fmt not in FORMATS:
            raise MediaError(f"{name!r}: format must be one of {tuple(FORMATS)}")
        if not isinstance(b64, str) or not b64:
            raise MediaError(f"{name!r}: data_base64 is required")
        try:
            data = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            raise MediaError(f"{name!r}: data_base64 is not valid base64") from None
        if not 1 <= len(data) <= MAX_FILE_BYTES:
            raise MediaError(f"{name!r}: a file must be 1 to {MAX_FILE_BYTES} bytes")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise MediaError(f"the files together exceed {MAX_TOTAL_BYTES} bytes")
        dt = m.get("declared_text", "")
        if not isinstance(dt, str) or len(dt) > 2000 or "\x00" in dt:
            raise MediaError(f"{name!r}: declared_text must be text of at most 2000 characters")
        _check_bytes(fmt, data, name)
        out.append(Media(name, fmt, data, dt))
    return tuple(out)


def content_parts(provider: str, text: str, media: tuple[Media, ...]) -> list[dict]:
    """The first user message of a multimodal case, in the provider's wire format. The text comes from the library."""
    if provider == "anthropic":
        return [{"type": "image", "source": {"type": "base64", "media_type": m.mime, "data": base64.b64encode(m.data).decode()}} for m in media] + [{"type": "text", "text": text}]
    parts: list[dict] = [{"type": "text", "text": text}]
    for m in media:
        b64 = base64.b64encode(m.data).decode()
        if m.kind == "image":
            parts.append({"type": "image_url", "image_url": {"url": f"data:{m.mime};base64,{b64}"}})
        else:
            parts.append({"type": "input_audio", "input_audio": {"data": b64, "format": m.format}})
    return parts


def wire_chars(wire: list[dict]) -> int:
    """Size of the request for the Governor: text counts as it is, every attached file as a fixed estimate (never its base64 length)."""
    import json
    total = 0
    for msg in wire:
        c = msg.get("content")
        if isinstance(c, str):
            total += len(c) + (len(json.dumps(msg["tool_calls"], ensure_ascii=False)) if msg.get("tool_calls") else 0)
        elif isinstance(c, list) and any(isinstance(p, dict) and p.get("type") in ("image", "image_url", "input_audio") for p in c):
            for p in c:
                t = p.get("type") if isinstance(p, dict) else None
                total += len(p.get("text", "")) if t == "text" else COST_CHARS["audio" if t == "input_audio" else "image"] if t in ("image", "image_url", "input_audio") else len(json.dumps(p))
        else:
            total += len(json.dumps(msg, ensure_ascii=False))
    return total


# ------------------------------------------------------------------------------------------------ static pre-processing
def ocr_available() -> bool:
    return shutil.which("tesseract") is not None


def _ocr(m: Media) -> tuple[str, str]:
    """-> (text, status). status: ok | unavailable | failed. The file is only read, never altered; Tesseract runs without a shell."""
    if not ocr_available():
        return "", "unavailable"
    from PIL import Image
    try:
        with Image.open(io.BytesIO(m.data)) as im:
            buf = io.BytesIO()
            im.convert("RGB").save(buf, "PNG")
        r = subprocess.run(["tesseract", "stdin", "stdout", "--psm", "6"], input=buf.getvalue(), capture_output=True, timeout=OCR_TIMEOUT, check=False)
        return r.stdout.decode("utf-8", "replace").strip()[:MAX_TEXT], "ok" if r.returncode == 0 else "failed"
    except Exception:  # noqa: BLE001
        return "", "failed"


def _image_metadata(m: Media) -> str:
    from PIL import Image
    parts: list[str] = []
    try:
        with Image.open(io.BytesIO(m.data)) as im:
            for k, v in (im.info or {}).items():
                if isinstance(v, str) and k not in ("dpi",):
                    parts.append(f"{k}: {v}")
                elif isinstance(v, bytes) and k == "comment":
                    parts.append(f"comment: {v.decode('utf-8', 'replace')}")
            try:
                for k, v in im.getexif().items():
                    if isinstance(v, str):
                        parts.append(f"exif {k}: {v}")
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(parts)[:MAX_TEXT]


def _audio_metadata(m: Media) -> tuple[str, dict]:
    facts: dict = {}
    if m.format == "wav":
        with wave.open(io.BytesIO(m.data)) as w:
            facts = {"channels": w.getnchannels(), "sample_rate": w.getframerate(), "seconds": round(w.getnframes() / max(1, w.getframerate()), 2)}
    head = m.data[:8192] if m.format == "mp3" else m.data[:4096]
    strings = re.findall(rb"[\x20-\x7e]{6,}", head)
    return "\n".join(s.decode() for s in strings[:20])[:MAX_TEXT], facts


def _norm(s: str) -> str:
    return " ".join(s.split()).casefold()


def preflight(media: tuple[Media, ...], canaries: tuple[str, ...] | list[str]) -> dict:
    """Static look at every file BEFORE it is sent. Returns the evidence block; `blocked` is true when a canary sits inside a file."""
    files, blocked = [], False
    for m in media:
        info: dict = {"name": m.name, "format": m.format, "kind": m.kind, "bytes": len(m.data), "sha256": m.sha256}
        if m.kind == "image":
            ocr, status = _ocr(m)
            meta = _image_metadata(m)
            info |= {"ocr_status": status, "ocr_text": ocr, "metadata_text": meta}
            carried = (ocr + "\n" + meta).strip()
        else:
            meta, facts = _audio_metadata(m)
            info |= {"speech": "not_inspected", "audio": facts, "metadata_text": meta}
            carried = meta
        c_hits = [c for c in canaries if c and _norm(c) in _norm(carried)]
        words = {w for w in re.findall(r"[a-z0-9]{4,}", _norm(carried))}
        declared = {w for w in re.findall(r"[a-z0-9]{4,}", _norm(m.declared_text))}
        undeclared = sorted(words - declared)
        info |= {"canary_in_file": len(c_hits), "undeclared_words": undeclared[:30], "undeclared_count": len(undeclared),
                 "carries_undeclared_text": len(undeclared) >= 3}
        blocked = blocked or bool(c_hits)
        files.append(info)
    return {"files": files, "blocked": blocked, "ocr_available": ocr_available(),
            "note": "Static pre-processing only: text from OCR and metadata. Audio speech is not transcribed. The files are sent exactly as the library holds them."}


def judge_note(pre: dict) -> str:
    """One short line for the judge's context (data, not instructions): what the carrier files showed."""
    bits = []
    for f in pre["files"]:
        txt = (f.get("ocr_text") or f.get("metadata_text") or "").replace("\n", " ")[:300]
        bits.append(f"{f['kind']} {f['name']}" + (f" (text found by pre-processing: {txt!r})" if txt else ""))
    return "[attached to the message: " + "; ".join(bits) + "]"
