"""
Turns an uploaded PDF, DOCX or EML file into its VISIBLE TEXT only. The original file is never forwarded: the text is re-rendered by docrender.py
(no scripts, macros, links, images, attachments or compression), so whatever a file carries besides readable text does not reach the target.

  * DOCX: text runs only; runs marked hidden (w:vanish) are skipped and counted. XML is parsed with defusedxml (no DTD, no entities).
  * PDF:  text extraction with pypdf (no rendering, no JavaScript, no attachments). Text that is merely drawn white or tiny cannot be told apart from
          normal text by an extractor; the preview shows exactly what was extracted so the operator can check it.
  * EML:  the From/To/Subject/Date headers and the text body (plain, or text taken from the HTML part with hidden elements skipped); attachments are ignored.
  * Invisible or formatting characters (zero-width, direction overrides, tag characters, other control characters) make the file be REFUSED, never silently cleaned.
"""
import email
import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass, field
from email import policy
from html.parser import HTMLParser

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_CHARS = 50_000
MAX_PDF_PAGES = 200
MAX_ZIP_ENTRIES = 500
MAX_XML_BYTES = 10 * 1024 * 1024
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


class ExtractError(ValueError):
    pass


@dataclass
class Extracted:
    format: str                       # pdf | docx | eml
    text: str
    notes: list[str] = field(default_factory=list)


def _check_visible(text: str) -> str:
    bad: dict[str, int] = {}
    for ch in text:
        o = ord(ch)
        if ch in "\n\r\t":
            continue
        if unicodedata.category(ch) in ("Cf", "Cc", "Co", "Cs") or o == 0x2028 or o == 0x2029:
            bad[f"U+{o:04X}"] = bad.get(f"U+{o:04X}", 0) + 1
    if bad:
        shown = ", ".join(f"{k} x{v}" for k, v in sorted(bad.items())[:5])
        raise ExtractError(f"The file contains invisible or control characters ({shown}). Only plain visible text is accepted: remove them and upload again.")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text).strip()
    if not text:
        raise ExtractError("No readable text was found in the file.")
    if len(text) > MAX_CHARS:
        raise ExtractError(f"The text has {len(text):,} characters; the limit is {MAX_CHARS:,}. Upload a shorter document.")
    return text


def _docx(data: bytes) -> Extracted:
    from defusedxml import ElementTree as ET
    from defusedxml.common import DefusedXmlException
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ExtractError("This is not a valid DOCX file.") from None
    infos = z.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ExtractError("The DOCX archive has too many entries.")
    try:
        info = z.getinfo("word/document.xml")
    except KeyError:
        raise ExtractError("This is not a Word document (word/document.xml is missing).") from None
    if info.file_size > MAX_XML_BYTES or (info.compress_size and info.file_size / info.compress_size > 200):
        raise ExtractError("The document body is too large or compressed suspiciously.")
    try:
        root = ET.fromstring(z.read(info), forbid_dtd=True)
    except (ET.ParseError, DefusedXmlException):
        raise ExtractError("The Word document could not be read safely.") from None
    hidden, lines = 0, []
    for p in root.iter(W + "p"):
        parts = []
        for r in p.iter(W + "r"):
            props = r.find(W + "rPr")
            if props is not None and props.find(W + "vanish") is not None:
                hidden += 1
                continue
            for el in r:
                if el.tag == W + "t" and el.text:
                    parts.append(el.text)
                elif el.tag == W + "tab":
                    parts.append("\t")
                elif el.tag == W + "br":
                    parts.append("\n")
        lines.append("".join(parts))
    notes = [f"{hidden} hidden text run(s) were skipped."] if hidden else []
    return Extracted("docx", _check_visible("\n".join(lines)), notes)


def _pdf(data: bytes) -> Extracted:
    try:
        from pypdf import PdfReader
        from pypdf.errors import PyPdfError
    except ImportError:                                                       # pragma: no cover
        raise ExtractError("PDF support is not installed on this server (pypdf).") from None
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise ExtractError("Encrypted PDF files are not accepted.")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise ExtractError(f"The PDF has more than {MAX_PDF_PAGES} pages.")
        text = "\n\n".join((pg.extract_text() or "") for pg in reader.pages)
    except ExtractError:
        raise
    except (PyPdfError, ValueError, KeyError, TypeError, RecursionError, OSError):
        raise ExtractError("The PDF could not be read.") from None
    return Extracted("pdf", _check_visible(text), ["Extracted text is shown below: compare it with the file if its layout matters."])


class _VisibleText(HTMLParser):
    HIDE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![\d.])|opacity\s*:\s*0(?![\d.])", re.I)
    SKIP = {"script", "style", "head", "template", "noscript"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.stack: list[bool] = []
        self.hidden_elements = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("br", "p", "div", "li", "tr"):
            self.out.append("\n")
        if tag in ("br", "img", "hr", "meta", "link", "input"):
            return
        a = dict(attrs)
        hide = tag in self.SKIP or "hidden" in a or bool(self.HIDE.search(a.get("style") or ""))
        self.hidden_elements += hide and tag not in self.SKIP
        self.stack.append(hide)

    def handle_endtag(self, tag):
        if tag in ("p", "div", "li", "tr"):
            self.out.append("\n")
        if self.stack and tag not in ("br", "img", "hr", "meta", "link", "input"):
            self.stack.pop()

    def handle_data(self, d):
        if not any(self.stack):
            self.out.append(d)


def _eml(data: bytes) -> Extracted:
    try:
        msg = email.message_from_bytes(data, policy=policy.default)
    except Exception:  # noqa: BLE001
        raise ExtractError("This is not a readable e-mail file.") from None
    notes = []
    head = []
    for h in ("From", "To", "Subject", "Date"):
        v = msg.get(h)
        if v:
            head.append(f"{h}: {' '.join(str(v).split())[:200]}")
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is None:
        raise ExtractError("The e-mail has no text body.")
    raw = body.get_content()
    if body.get_content_subtype() == "html":
        p = _VisibleText()
        p.feed(raw)
        raw = "".join(p.out)
        if p.hidden_elements:
            notes.append(f"{p.hidden_elements} hidden HTML element(s) were skipped.")
    atts = sum(1 for _ in msg.iter_attachments())
    if atts:
        notes.append(f"{atts} attachment(s) were ignored.")
    return Extracted("eml", _check_visible("\n".join(head) + "\n\n" + raw), notes)


def extract(filename: str, data: bytes) -> Extracted:
    if not data:
        raise ExtractError("The file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ExtractError(f"The file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    name = (filename or "").lower()
    if data[:5] == b"%PDF-" and name.endswith(".pdf"):
        return _pdf(data)
    if data[:4] == b"PK\x03\x04" and name.endswith(".docx"):
        return _docx(data)
    if name.endswith(".eml"):
        return _eml(data)
    raise ExtractError("Supported files: PDF (.pdf), Word (.docx) and e-mail (.eml).")
