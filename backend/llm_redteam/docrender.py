"""
Document rendering for indirect (ingest) tests: turns the operator's plain visible text into a TEXT-BASED file in one of six formats.

Safety by construction: the output is built here from escaped text only. There is no scripting, no macros, no embedded files, no links or actions,
no images, no external references, and no compression (so the bytes are small, predictable and easy to inspect). Nothing is hidden: what the
operator wrote is exactly what a person opening the file would read. Formats: txt, md, html, csv, pdf, docx.
"""
import csv
import html
import io
import zipfile

FORMATS = ("txt", "md", "html", "csv", "pdf", "docx", "eml")
BINARY = ("pdf", "docx")
EXT = {f: f for f in FORMATS}
CONTENT_TYPE = {"txt": "text/plain", "md": "text/markdown", "html": "text/html", "csv": "text/csv", "pdf": "application/pdf",
                "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "eml": "message/rfc822"}
MAX_DOC_BYTES = 1_000_000
MAX_CSV_ROWS, MAX_CSV_COLS, MAX_CSV_CELL = 5000, 50, 2000
MAX_PDF_PAGES = 200
LINE_CHARS, LINES_PER_PAGE = 92, 52


class DocError(ValueError):
    pass


def check_text(text: str) -> str:
    """Visible text only: line breaks and tabs are fine, other control characters (and bidirectional overrides) are not."""
    for ch in text:
        o = ord(ch)
        if (o < 32 and ch not in "\n\r\t") or o == 127 or 0x202A <= o <= 0x202E or 0x2066 <= o <= 0x2069 or o == 0xFEFF:
            raise DocError(f"the text contains a control or direction-override character (U+{o:04X}); only visible text is allowed")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def with_extension(name: str, fmt: str) -> str:
    return name if name.lower().endswith("." + EXT[fmt]) else f"{name}.{EXT[fmt]}"


def _wrap(text: str) -> list[str]:
    out = []
    for para in text.split("\n"):
        line = para.expandtabs(4)
        while len(line) > LINE_CHARS:
            cut = line.rfind(" ", 0, LINE_CHARS)
            cut = cut if cut > 20 else LINE_CHARS
            out.append(line[:cut].rstrip())
            line = line[cut:].lstrip()
        out.append(line)
    return out


def _csv(text: str) -> bytes:
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or len(rows) > MAX_CSV_ROWS or any(len(r) > MAX_CSV_COLS or any(len(c) > MAX_CSV_CELL for c in r) for r in rows):
        raise DocError(f"CSV must have 1-{MAX_CSV_ROWS} rows, at most {MAX_CSV_COLS} columns and cells up to {MAX_CSV_CELL} characters")

    def safe(c: str) -> str:                                    # spreadsheet formula neutralisation (a leading quote makes the cell plain text)
        return "'" + c if c[:1] in ("=", "+", "@") or (c[:1] == "-" and not c[1:2].isdigit() and c[1:2] != ".") else c
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\r\n").writerows([[safe(c) for c in r] for r in rows])
    return buf.getvalue().encode("utf-8")


def _html(text: str, title: str) -> bytes:
    paras = "\n".join("<p>" + "<br>\n".join(html.escape(ln) for ln in p.split("\n")) + "</p>" for p in text.split("\n\n") if p.strip())
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>{html.escape(title)}</title></head>\n<body>\n{paras}\n</body></html>\n').encode("utf-8")


def _eml(text: str, title: str) -> bytes:
    """A plain-text e-mail with fixed, neutral headers; the operator's text is the body. Nothing hidden: no HTML part, no attachments, no extra headers."""
    subject = "".join(ch for ch in " ".join(title.split()) if ch.isprintable() and ord(ch) < 127)[:100] or "Message"
    head = f"From: sender@example.test\r\nTo: recipient@example.test\r\nSubject: {subject}\r\nDate: Mon, 01 Jan 2024 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
    return (head + text.replace("\n", "\r\n") + "\r\n").encode("utf-8")


def _pdf_escape(s: str) -> str:
    return s.encode("latin-1", "replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf(text: str) -> bytes:
    lines = _wrap(text)
    pages = [lines[i:i + LINES_PER_PAGE] for i in range(0, len(lines), LINES_PER_PAGE)] or [[""]]
    if len(pages) > MAX_PDF_PAGES:
        raise DocError(f"the PDF would have more than {MAX_PDF_PAGES} pages")
    objs: list[bytes] = [b"", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]   # 1 catalog, 2 pages, 3 font (filled below)
    kids = []
    for pg in pages:
        body = "BT /F1 11 Tf 14 TL 50 790 Td\n" + "\n".join(f"({_pdf_escape(ln)}) '" for ln in pg) + "\nET"
        stream = body.encode("latin-1", "replace")
        pid, cid = len(objs) + 1, len(objs) + 2
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {cid} 0 R >>".encode())
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        kids.append(f"{pid} 0 R")
    objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode()
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode() + b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    return bytes(out)


def _docx(text: str) -> bytes:
    esc = lambda s: html.escape(s, quote=False)  # noqa: E731
    paras = "".join(f'<w:p><w:r><w:t xml:space="preserve">{esc(ln)}</w:t></w:r></w:p>' for ln in text.split("\n"))
    parts = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{paras}</w:body></w:document>',
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:                # stored (not compressed) and a fixed timestamp: small, inspectable, reproducible
        for name, data in parts.items():
            zi = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data.encode("utf-8"))
    return buf.getvalue()


def render(fmt: str, text: str, title: str = "document") -> bytes:
    """The file bytes for `text` in format `fmt`; raises DocError when the text or the result is not acceptable."""
    if fmt not in FORMATS:
        raise DocError(f"format must be one of {FORMATS}")
    text = check_text(text)
    data = {"txt": lambda: text.encode("utf-8"), "md": lambda: text.encode("utf-8"), "html": lambda: _html(text, title), "csv": lambda: _csv(text),
            "pdf": lambda: _pdf(text), "docx": lambda: _docx(text), "eml": lambda: _eml(text, title)}[fmt]()
    if len(data) > MAX_DOC_BYTES:
        raise DocError(f"the rendered file is larger than {MAX_DOC_BYTES} bytes")
    return data
