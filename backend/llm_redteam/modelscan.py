"""
Model supply-chain scanner: STATIC analysis of model files. Nothing is ever loaded, unpickled, imported or executed.

Pickle-based formats (.pkl, .pickle, .pt, .pth, .bin, .ckpt) can run arbitrary code when loaded. This module walks the pickle opcode stream
with `pickletools.genops` (a pure parser), reconstructs which module.name globals the file would import, and classifies them.

What it can say:   a file imports a code-execution primitive (os.system, subprocess, eval, ...) / imports something unknown / is code-free.
What it CANNOT say: whether numeric weights are poisoned or backdoored. That is not detectable by static inspection of a file; the report
                    says so explicitly and records the SHA-256 so provenance can be checked against a hash published by the model's owner.
"""
import hashlib
import io
import json
import pickletools
import struct
import zipfile
from dataclasses import dataclass, field

MAX_BYTES = 32 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
MAX_PICKLE_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 200
PICKLE_SUFFIXES = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib")

# modules whose import from a model file is a code-execution / exfiltration primitive
DANGEROUS_MODULES = {"os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty", "ctypes", "importlib", "runpy", "code", "codeop",
                     "marshal", "pickle", "_pickle", "webbrowser", "urllib", "urllib2", "http", "ftplib", "smtplib", "telnetlib", "requests",
                     "httplib", "multiprocessing", "threading", "tempfile", "pathlib", "glob", "platform", "signal", "commands", "pdb", "timeit",
                     "asyncio", "zipfile", "tarfile", "builtins", "__builtin__", "__builtins__"}
DANGEROUS_BUILTINS = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "delattr", "globals", "locals", "input", "breakpoint", "vars"}
DANGEROUS_QUALIFIED = {("operator", "attrgetter"), ("operator", "methodcaller"), ("types", "FunctionType"), ("types", "CodeType"),
                       ("functools", "partial"), ("numpy.testing._private.utils", "runstring"), ("torch.utils.bottleneck.__main__", "run_cprofile"),
                       ("torch.jit", "load"), ("torch", "load"), ("base64", "b64decode")}
# well-known harmless globals found in ordinary PyTorch / NumPy checkpoints
SAFE_GLOBALS = {("collections", "OrderedDict"), ("collections", "defaultdict"), ("torch._utils", "_rebuild_tensor_v2"), ("torch._utils", "_rebuild_tensor"),
                ("torch._utils", "_rebuild_parameter"), ("torch._utils", "_rebuild_parameter_with_state"), ("torch._utils", "_rebuild_device_tensor_from_numpy"),
                ("torch", "Size"), ("torch", "device"), ("torch", "dtype"), ("torch.nn.parameter", "Parameter"),
                ("numpy", "dtype"), ("numpy", "ndarray"), ("numpy.core.multiarray", "_reconstruct"), ("numpy.core.multiarray", "scalar"),
                ("numpy._core.multiarray", "_reconstruct"), ("numpy._core.multiarray", "scalar")}
SAFE_PREFIXES = (("torch", "FloatStorage"), ("torch", "HalfStorage"), ("torch", "BFloat16Storage"), ("torch", "LongStorage"), ("torch", "IntStorage"),
                 ("torch", "ByteStorage"), ("torch", "DoubleStorage"), ("torch", "BoolStorage"), ("torch", "ShortStorage"), ("torch", "CharStorage"))

STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"}
SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "info": 0}


class ScanError(ValueError):
    pass


@dataclass
class Finding:
    severity: str            # critical | high | medium | info
    code: str
    message: str
    location: str = ""

    def to_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code, "message": self.message, "location": self.location}


@dataclass
class ScanResult:
    filename: str
    size: int
    sha256: str
    format: str
    verdict: str = "clean"          # unsafe | suspicious | clean | unsupported
    findings: list[Finding] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)
    hash_match: bool | None = None

    def add(self, sev: str, code: str, msg: str, loc: str = "") -> None:
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(Finding(sev, code, msg, loc))

    def finish(self) -> "ScanResult":
        top = max((SEVERITY_ORDER[f.severity] for f in self.findings), default=0)
        if self.format == "unsupported":
            self.verdict = "unsupported"
        elif top >= 2:
            self.verdict = "unsafe"
        elif top == 1:
            self.verdict = "suspicious"
        else:
            self.verdict = "clean"
        self.limits.append("Static analysis cannot detect poisoned or backdoored weights. Compare the SHA-256 with the hash published by the model's owner and "
                           "evaluate the model's behavior with the test library.")
        return self

    def to_dict(self) -> dict:
        return {"filename": self.filename, "size": self.size, "sha256": self.sha256, "format": self.format, "verdict": self.verdict,
                "hash_match": self.hash_match, "findings": [f.to_dict() for f in self.findings], "imports": self.imports, "limits": self.limits}


def classify_global(module: str, name: str) -> tuple[str, str] | None:
    """(severity, reason) for a pickle global, or None when it is a known-harmless one."""
    root = module.split(".")[0]
    if (module, name) in SAFE_GLOBALS or (module, name) in SAFE_PREFIXES:
        return None
    if module in ("torch", "torch._utils") and name.endswith("Storage"):
        return None
    if (module, name) in DANGEROUS_QUALIFIED:
        return "critical", f"{module}.{name} can execute or reach code"
    if module in DANGEROUS_MODULES or root in DANGEROUS_MODULES:
        return "critical", f"imports {module}.{name} (code execution / system / network access)"
    if name in DANGEROUS_BUILTINS and module in ("builtins", "__builtin__"):
        return "critical", f"{module}.{name} is a code-execution primitive"
    return "medium", f"imports {module}.{name}, which is not a known-harmless checkpoint global"


def scan_pickle(data: bytes, res: ScanResult, loc: str = "") -> None:
    """Walks the opcode stream. Never executes it."""
    if len(data) > MAX_PICKLE_BYTES:
        res.add("medium", "PICKLE_TOO_LARGE", "pickle stream larger than the scan limit; only the beginning was inspected", loc)
        data = data[:MAX_PICKLE_BYTES]
    recent: list[str] = []          # last string pushes, for STACK_GLOBAL
    memo: dict[int, str] = {}
    seen: set[tuple[str, str]] = set()
    reduce_count = 0
    last_str = None

    def hit(module: str, name: str) -> None:
        if (module, name) in seen:
            return
        seen.add((module, name))
        res.imports.append(f"{module}.{name}")
        c = classify_global(module, name)
        if c:
            res.add(c[0], "PICKLE_DANGEROUS_GLOBAL" if c[0] == "critical" else "PICKLE_UNKNOWN_GLOBAL", c[1], loc)

    try:
        for op, arg, _pos in pickletools.genops(io.BytesIO(data)):
            n = op.name
            if n in STRING_OPS and isinstance(arg, str):
                recent = (recent + [arg])[-2:]
                last_str = arg
            elif n in ("MEMOIZE",) and last_str is not None:
                memo[len(memo)] = last_str
            elif n in ("BINPUT", "LONG_BINPUT", "PUT") and last_str is not None:
                memo[int(arg)] = last_str
            elif n in ("BINGET", "LONG_BINGET", "GET") and int(arg) in memo:
                recent = (recent + [memo[int(arg)]])[-2:]
            elif n in ("GLOBAL", "INST") and isinstance(arg, str):
                m, _, nm = arg.replace("\n", " ").partition(" ")
                hit(m, nm)
            elif n == "STACK_GLOBAL":
                if len(recent) == 2:
                    hit(recent[0], recent[1])
                else:
                    res.add("high", "PICKLE_OPAQUE_GLOBAL", "STACK_GLOBAL whose module/name could not be determined statically (obfuscated import)", loc)
            elif n in ("REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD") and n != "BUILD":
                reduce_count += 1
            elif n == "EXT1" or n == "EXT2" or n == "EXT4":
                res.add("medium", "PICKLE_EXTENSION_REGISTRY", "uses the pickle extension registry (indirect global lookup)", loc)
    except Exception as e:  # noqa: BLE001
        res.add("medium", "PICKLE_MALFORMED", f"the pickle stream could not be fully parsed ({type(e).__name__}); contents after that point are unverified", loc)
    if reduce_count and any(f.code == "PICKLE_DANGEROUS_GLOBAL" for f in res.findings):
        res.add("critical", "PICKLE_CALLS_DANGEROUS", "a dangerous global is imported AND the stream contains call opcodes (REDUCE/OBJ/NEWOBJ): loading this file would run code", loc)


def _scan_zip(data: bytes, res: ScanResult) -> None:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        res.add("medium", "ZIP_MALFORMED", "the archive is damaged")
        return
    infos = z.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        res.add("medium", "ZIP_TOO_MANY_ENTRIES", f"{len(infos)} entries; only the first {MAX_ZIP_ENTRIES} were inspected")
        infos = infos[:MAX_ZIP_ENTRIES]
    total = sum(i.file_size for i in infos)
    if total > 8 * 1024 * 1024 * 1024 or (len(data) and total / len(data) > 2000):
        res.add("high", "ZIP_BOMB_RATIO", "extreme compression ratio / declared size; entries were not decompressed")
        return
    pk = 0
    for i in infos:
        n = i.filename
        if n.startswith("/") or ".." in n.split("/") or "\\" in n:
            res.add("high", "ZIP_PATH_TRAVERSAL", f"entry name tries to leave its folder: {n!r}", n[:120])
        if n.endswith((".py", ".so", ".dll", ".exe", ".sh", ".pyc")):
            res.add("high", "ARCHIVE_EXECUTABLE", "the archive contains an executable/script file", n[:120])
        if n.lower().endswith((".pkl", ".pickle")) or n.endswith("/data.pkl") or n == "data.pkl":
            pk += 1
            if i.file_size > MAX_PICKLE_BYTES:
                res.add("medium", "PICKLE_TOO_LARGE", "pickle entry exceeds the scan limit", n[:120])
                continue
            with z.open(i) as fh:
                scan_pickle(fh.read(MAX_PICKLE_BYTES + 1), res, n[:120])
    if not pk:
        res.add("info", "NO_PICKLE_IN_ARCHIVE", "no pickle entry found in the archive")


def _scan_safetensors(data: bytes, res: ScanResult) -> None:
    (n,) = struct.unpack("<Q", data[:8])
    if n > 100 * 1024 * 1024 or 8 + n > len(data):
        res.add("high", "SAFETENSORS_BAD_HEADER", "the header length is impossible")
        return
    try:
        hdr = json.loads(data[8:8 + n].decode())
    except Exception:  # noqa: BLE001
        res.add("high", "SAFETENSORS_BAD_HEADER", "the header is not valid JSON")
        return
    end = 0
    for k, v in hdr.items():
        if k == "__metadata__":
            continue
        try:
            a, b = v["data_offsets"]
            end = max(end, b)
        except Exception:  # noqa: BLE001
            res.add("high", "SAFETENSORS_BAD_TENSOR", f"tensor {k[:60]!r} has no valid data_offsets")
            return
    if 8 + n + end != len(data):
        res.add("medium", "SAFETENSORS_TRAILING_DATA", "the file size does not match the declared tensors (extra or missing bytes)")
    res.add("info", "SAFETENSORS_OK", "safetensors stores raw tensors only: it cannot contain executable code")


def detect_format(filename: str, data: bytes) -> str:
    if data[:4] == b"PK\x03\x04":
        return "zip-pickle" if filename.lower().endswith(PICKLE_SUFFIXES + (".zip",)) else "zip"
    if data[:4] == b"GGUF":
        return "gguf"
    if data[:6] == b"\x93NUMPY":
        return "numpy"
    if data[:1] == b"\x80" and len(data) > 2 and data[1] in range(2, 6):
        return "pickle"
    if filename.lower().endswith(".safetensors") and len(data) >= 8:
        return "safetensors"
    if filename.lower().endswith(PICKLE_SUFFIXES):
        return "pickle"                       # legacy protocol 0/1 pickles have no magic: still scanned as pickle
    return "unsupported"


def scan_bytes(filename: str, data: bytes, expected_sha256: str | None = None) -> ScanResult:
    if not data:
        raise ScanError("the file is empty")
    if len(data) > MAX_BYTES:
        raise ScanError(f"the file is larger than {MAX_BYTES // (1024 * 1024)} MB")
    name = (filename or "model").replace("\\", "/").split("/")[-1][:200]
    res = ScanResult(name, len(data), hashlib.sha256(data).hexdigest(), detect_format(name, data))
    if expected_sha256:
        res.hash_match = res.sha256 == expected_sha256.strip().lower()
        if not res.hash_match:
            res.add("high", "HASH_MISMATCH", "the SHA-256 differs from the expected value: this is not the file the owner published")
    if res.format in ("zip-pickle", "zip"):
        _scan_zip(data, res)
    elif res.format == "pickle":
        scan_pickle(data, res)
    elif res.format == "safetensors":
        _scan_safetensors(data, res)
    elif res.format == "numpy":
        if b"'descr': '|O'" in data[:512] or b"\"descr\": \"|O\"" in data[:512]:
            res.add("high", "NUMPY_OBJECT_ARRAY", "object-dtype arrays are stored as pickles: loading with allow_pickle can run code")
            off = data.find(b"\x80", 10)
            if off > 0:
                scan_pickle(data[off:], res, "npy-object")
        else:
            res.add("info", "NUMPY_OK", "plain numeric array")
    elif res.format == "gguf":
        res.add("info", "GGUF_NO_CODE", "GGUF holds tensors and metadata, not executable code (chat templates in metadata are text and were not evaluated)")
    else:
        res.add("info", "UNSUPPORTED_FORMAT", "the format is not recognized; no verdict was possible")
    return res.finish()
